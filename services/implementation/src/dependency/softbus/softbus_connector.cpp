/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "softbus_connector.h"

#include <securec.h>
#include <unistd.h>

#include "dm_anonymous.h"
#include "dm_constants.h"
#include "dm_crypto.h"
#include "dm_device_info.h"
#include "dm_log.h"
#include "dm_radar_helper.h"
#include "dm_softbus_cache.h"
#include "nlohmann/json.hpp"
#include "parameter.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DistributedHardware {
const int32_t SOFTBUS_SUBSCRIBE_ID_MASK = 0x0000FFFF;
const int32_t SOFTBUS_DISCOVER_DEVICE_INFO_MAX_SIZE = 100;
const int32_t SOFTBUS_TRUSTDEVICE_UUIDHASH_INFO_MAX_SIZE = 100;

constexpr const char* WIFI_IP = "WIFI_IP";
constexpr const char* WIFI_PORT = "WIFI_PORT";
constexpr const char* BR_MAC = "BR_MAC";
constexpr const char* BLE_MAC = "BLE_MAC";
constexpr const char* ETH_IP = "ETH_IP";
constexpr const char* ETH_PORT = "ETH_PORT";

std::string SoftbusConnector::remoteUdidHash_ = "";
std::map<std::string, std::shared_ptr<DeviceInfo>> SoftbusConnector::discoveryDeviceInfoMap_ = {};
std::unordered_map<std::string, std::string> SoftbusConnector::deviceUdidMap_ = {};
std::vector<ProcessInfo> SoftbusConnector::processInfoVec_ = {};
std::mutex SoftbusConnector::discoveryDeviceInfoMutex_;
std::mutex SoftbusConnector::deviceUdidLocks_;
std::mutex SoftbusConnector::processInfoVecMutex_;

SoftbusConnector::SoftbusConnector()
{
#if !(defined(__LITEOS_M__) || defined(LITE_DEVICE))
    softbusSession_ = std::make_shared<SoftbusSession>();
#endif
    LOGD("SoftbusConnector constructor.");
}

SoftbusConnector::~SoftbusConnector()
{
    LOGD("SoftbusConnector destructor.");
}

int32_t SoftbusConnector::RegisterSoftbusStateCallback(const std::shared_ptr<ISoftbusStateCallback> callback)
{
    deviceStateManagerCallback_ = callback;
    return DM_OK;
}

int32_t SoftbusConnector::UnRegisterSoftbusStateCallback()
{
    deviceStateManagerCallback_ = nullptr;
    return DM_OK;
}

void SoftbusConnector::JoinLnn(const std::string &deviceId)
{
    std::string connectAddr;
    LOGI("start, deviceId: %{public}s.", GetAnonyString(deviceId).c_str());
    ConnectionAddr *addrInfo = GetConnectAddr(deviceId, connectAddr);
    if (addrInfo == nullptr) {
        LOGE("addrInfo is nullptr.");
        return;
    }
    if (Crypto::ConvertHexStringToBytes(addrInfo->info.ble.udidHash, UDID_HASH_LEN,
        remoteUdidHash_.c_str(), remoteUdidHash_.length()) != DM_OK) {
        LOGE("convert remoteUdid hash failed, remoteUdidHash_: %{public}s.", GetAnonyString(remoteUdidHash_).c_str());
        return;
    }
    int32_t ret = ::JoinLNN(DM_PKG_NAME, addrInfo, OnSoftbusJoinLNNResult);
    if (ret != DM_OK) {
        LOGE("[SOFTBUS]JoinLNN failed, ret: %{public}d.", ret);
    }
    return;
}

void SoftbusConnector::JoinLnnByHml(int32_t sessionId, int32_t sessionKeyId, int32_t remoteSessionKeyId)
{
    LOGI("start, JoinLnnByHml sessionId: %{public}d.", sessionId);
    ConnectionAddr addrInfo;
    addrInfo.type = CONNECTION_ADDR_SESSION_WITH_KEY;
    addrInfo.info.session.sessionId = sessionId;
    if (sessionKeyId > 0 && remoteSessionKeyId > 0) {
        addrInfo.info.session.localDeviceKeyId = sessionKeyId;
        addrInfo.info.session.remoteDeviceKeyId = remoteSessionKeyId;
        LOGI("sessionKeyId valid");
    } else {
        addrInfo.info.session.localDeviceKeyId = 0;
        addrInfo.info.session.remoteDeviceKeyId = 0;
    }
    int32_t ret = ::JoinLNN(DM_PKG_NAME, &addrInfo, OnSoftbusJoinLNNResult);
    if (ret != DM_OK) {
        LOGE("[SOFTBUS]JoinLNN failed, ret: %{public}d.", ret);
    }
}

int32_t SoftbusConnector::GetUdidByNetworkId(const char *networkId, std::string &udid)
{
    LOGI("start, networkId: %{public}s.", GetAnonyString(std::string(networkId)).c_str());
    return SoftbusCache::GetInstance().GetUdidFromCache(networkId, udid);
}

int32_t SoftbusConnector::GetUuidByNetworkId(const char *networkId, std::string &uuid)
{
    LOGI("start, networkId: %{public}s.", GetAnonyString(std::string(networkId)).c_str());
    return SoftbusCache::GetInstance().GetUuidFromCache(networkId, uuid);
}

#if !(defined(__LITEOS_M__) || defined(LITE_DEVICE))
std::shared_ptr<SoftbusSession> SoftbusConnector::GetSoftbusSession()
{
    return softbusSession_;
}
#endif

bool SoftbusConnector::HaveDeviceInMap(std::string deviceId)
{
    std::lock_guard<std::mutex> lock(discoveryDeviceInfoMutex_);
    auto iter = discoveryDeviceInfoMap_.find(deviceId);
    if (iter == discoveryDeviceInfoMap_.end()) {
        LOGE("deviceInfo not found by deviceId: %{public}s.", GetAnonyString(deviceId).c_str());
        return false;
    }
    return true;
}

ConnectionAddr *SoftbusConnector::GetConnectAddrByType(DeviceInfo *deviceInfo, ConnectionAddrType type)
{
    if (deviceInfo == nullptr) {
        return nullptr;
    }
    for (uint32_t i = 0; i < deviceInfo->addrNum; ++i) {
        if (deviceInfo->addr[i].type == type) {
            return &deviceInfo->addr[i];
        }
    }
    return nullptr;
}

ConnectionAddr *SoftbusConnector::GetConnectAddr(const std::string &deviceId, std::string &connectAddr)
{
    DeviceInfo *deviceInfo = nullptr;
    {
        std::lock_guard<std::mutex> lock(discoveryDeviceInfoMutex_);
        auto iter = discoveryDeviceInfoMap_.find(deviceId);
        if (iter == discoveryDeviceInfoMap_.end()) {
            LOGE("deviceInfo not found by deviceId: %{public}s.", GetAnonyString(deviceId).c_str());
            return nullptr;
        }
        deviceInfo = iter->second.get();
    }
    if (deviceInfo->addrNum <= 0 || deviceInfo->addrNum >= CONNECTION_ADDR_MAX) {
        LOGE("deviceInfo addrNum not valid, addrNum: %{public}d.", deviceInfo->addrNum);
        return nullptr;
    }
    nlohmann::json jsonPara;
    ConnectionAddr *addr = GetConnectAddrByType(deviceInfo, ConnectionAddrType::CONNECTION_ADDR_ETH);
    if (addr != nullptr) {
        LOGI("[SOFTBUS]get ETH ConnectionAddr for deviceId: %{public}s.", GetAnonyString(deviceId).c_str());
        jsonPara[ETH_IP] = addr->info.ip.ip;
        jsonPara[ETH_PORT] = addr->info.ip.port;
        connectAddr = SafetyDump(jsonPara);
        return addr;
    }
    addr = GetConnectAddrByType(deviceInfo, ConnectionAddrType::CONNECTION_ADDR_WLAN);
    if (addr != nullptr) {
        jsonPara[WIFI_IP] = addr->info.ip.ip;
        jsonPara[WIFI_PORT] = addr->info.ip.port;
        LOGI("[SOFTBUS]get WLAN ConnectionAddr for deviceId: %{public}s.", GetAnonyString(deviceId).c_str());
        connectAddr = SafetyDump(jsonPara);
        return addr;
    }
    addr = GetConnectAddrByType(deviceInfo, ConnectionAddrType::CONNECTION_ADDR_BR);
    if (addr != nullptr) {
        jsonPara[BR_MAC] = addr->info.br.brMac;
        LOGI("[SOFTBUS]get BR ConnectionAddr for deviceId: %{public}s.", GetAnonyString(deviceId).c_str());
        connectAddr = SafetyDump(jsonPara);
        return addr;
    }
    addr = GetConnectAddrByType(deviceInfo, ConnectionAddrType::CONNECTION_ADDR_BLE);
    if (addr != nullptr) {
        jsonPara[BLE_MAC] = addr->info.ble.bleMac;
        connectAddr = SafetyDump(jsonPara);
        return addr;
    }
    LOGE("[SOFTBUS]failed to get ConnectionAddr for deviceId: %{public}s.", GetAnonyString(deviceId).c_str());
    return nullptr;
}

void SoftbusConnector::ConvertDeviceInfoToDmDevice(const DeviceInfo &deviceInfo, DmDeviceInfo &dmDeviceInfo)
{
    if (memset_s(&dmDeviceInfo, sizeof(DmDeviceInfo), 0, sizeof(DmDeviceInfo)) != EOK) {
        LOGE("ConvertDeviceInfoToDmDevice memset_s failed.");
        return;
    }

    if (memcpy_s(dmDeviceInfo.deviceId, sizeof(dmDeviceInfo.deviceId), deviceInfo.devId,
                 std::min(sizeof(dmDeviceInfo.deviceId), sizeof(deviceInfo.devId))) != EOK) {
        LOGE("ConvertDeviceInfoToDmDevice copy deviceId data failed.");
        return;
    }

    if (memcpy_s(dmDeviceInfo.deviceName, sizeof(dmDeviceInfo.deviceName), deviceInfo.devName,
                 std::min(sizeof(dmDeviceInfo.deviceName), sizeof(deviceInfo.devName))) != EOK) {
        LOGE("ConvertDeviceInfoToDmDevice copy deviceName data failed.");
        return;
    }

    dmDeviceInfo.deviceTypeId = deviceInfo.devType;
    dmDeviceInfo.range = deviceInfo.range;
}

void SoftbusConnector::ConvertDeviceInfoToDmDevice(const DeviceInfo &deviceInfo, DmDeviceBasicInfo &dmDeviceBasicInfo)
{
    if (memset_s(&dmDeviceBasicInfo, sizeof(DmDeviceBasicInfo), 0, sizeof(DmDeviceBasicInfo)) != EOK) {
        LOGE("ConvertDeviceInfoToDmDevice memset_s failed.");
        return;
    }

    if (memcpy_s(dmDeviceBasicInfo.deviceId, sizeof(dmDeviceBasicInfo.deviceId), deviceInfo.devId,
                 std::min(sizeof(dmDeviceBasicInfo.deviceId), sizeof(deviceInfo.devId))) != EOK) {
        LOGE("ConvertDeviceInfoToDmDevice copy deviceId data failed.");
        return;
    }

    if (memcpy_s(dmDeviceBasicInfo.deviceName, sizeof(dmDeviceBasicInfo.deviceName), deviceInfo.devName,
                 std::min(sizeof(dmDeviceBasicInfo.deviceName), sizeof(deviceInfo.devName))) != EOK) {
        LOGE("ConvertDeviceInfoToDmDevice copy deviceName data failed.");
        return;
    }

    dmDeviceBasicInfo.deviceTypeId = deviceInfo.devType;
}

void SoftbusConnector::OnSoftbusJoinLNNResult(ConnectionAddr *addr, const char *networkId, int32_t result)
{
    (void)addr;
    (void)networkId;
    LOGD("[SOFTBUS]OnSoftbusJoinLNNResult, result: %{public}d.", result);
}

std::string SoftbusConnector::GetDeviceUdidByUdidHash(const std::string &udidHash)
{
    std::lock_guard<std::mutex> lock(deviceUdidLocks_);
    for (auto &iter : deviceUdidMap_) {
        if (iter.second == udidHash) {
            return iter.first;
        }
    }
    LOGE("fail to GetUdidByUdidHash, udidHash: %{public}s", GetAnonyString(udidHash).c_str());
    return udidHash;
}

std::string SoftbusConnector::GetDeviceUdidHashByUdid(const std::string &udid)
{
    {
        std::lock_guard<std::mutex> lock(deviceUdidLocks_);
        auto iter = deviceUdidMap_.find(udid);
        if (iter != deviceUdidMap_.end()) {
            return deviceUdidMap_[udid];
        }
    }

    char udidHash[DM_MAX_DEVICE_ID_LEN] = {0};
    if (Crypto::GetUdidHash(udid, reinterpret_cast<uint8_t *>(udidHash)) != DM_OK) {
        LOGE("get udidhash by udid: %{public}s failed.", GetAnonyString(udid).c_str());
        return "";
    }
    LOGI("get udidhash: %{public}s by udid: %{public}s.", GetAnonyString(udidHash).c_str(),
        GetAnonyString(udid).c_str());
    std::lock_guard<std::mutex> lock(deviceUdidLocks_);
    deviceUdidMap_[udid] = udidHash;
    return udidHash;
}

void SoftbusConnector::EraseUdidFromMap(const std::string &udid)
{
    std::lock_guard<std::mutex> lock(deviceUdidLocks_);
    auto iter = deviceUdidMap_.find(udid);
    if (iter == deviceUdidMap_.end()) {
        return;
    }
    size_t mapSize = deviceUdidMap_.size();
    if (mapSize >= SOFTBUS_TRUSTDEVICE_UUIDHASH_INFO_MAX_SIZE) {
        deviceUdidMap_.erase(udid);
    }
}

std::string SoftbusConnector::GetLocalDeviceName()
{
    NodeBasicInfo nodeBasicInfo;
    int32_t ret = GetLocalNodeDeviceInfo(DM_PKG_NAME, &nodeBasicInfo);
    if (ret != DM_OK) {
        LOGE("[SOFTBUS]GetLocalNodeDeviceInfo failed, ret: %{public}d.", ret);
        return "";
    }
    return nodeBasicInfo.deviceName;
}

int32_t SoftbusConnector::GetLocalDeviceTypeId()
{
    NodeBasicInfo nodeBasicInfo;
    int32_t ret = GetLocalNodeDeviceInfo(DM_PKG_NAME, &nodeBasicInfo);
    if (ret != DM_OK) {
        LOGE("[SOFTBUS]GetLocalNodeDeviceInfo failed, ret: %{public}d.", ret);
        return DmDeviceType::DEVICE_TYPE_UNKNOWN;
    }
    return nodeBasicInfo.deviceTypeId;
}

std::string SoftbusConnector::GetLocalDeviceNetworkId()
{
    NodeBasicInfo nodeBasicInfo;
    int32_t ret = GetLocalNodeDeviceInfo(DM_PKG_NAME, &nodeBasicInfo);
    if (ret != DM_OK) {
        LOGE("[SOFTBUS]GetLocalDeviceNetworkId failed, ret: %{public}d.", ret);
        return "";
    }
    return nodeBasicInfo.networkId;
}

int32_t SoftbusConnector::AddMemberToDiscoverMap(const std::string &deviceId, std::shared_ptr<DeviceInfo> deviceInfo)
{
    if (deviceId.empty()) {
        LOGE("AddMemberToDiscoverMap failed, deviceId is empty.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    std::lock_guard<std::mutex> lock(discoveryDeviceInfoMutex_);
    discoveryDeviceInfoMap_[deviceId] = std::move(deviceInfo);
    deviceInfo = nullptr;
    return DM_OK;
}

std::string SoftbusConnector::GetNetworkIdByDeviceId(const std::string &deviceId)
{
    LOGI("SoftbusConnector::GetNetworkIdByDeviceId");
    int32_t deviceCount = 0;
    NodeBasicInfo *nodeInfo = nullptr;
    if (GetAllNodeDeviceInfo(DM_PKG_NAME, &nodeInfo, &deviceCount) != DM_OK) {
        LOGE("[SOFTBUS]GetAllNodeDeviceInfo failed.");
        return "";
    }
    for (int32_t i = 0; i < deviceCount; ++i) {
        NodeBasicInfo *nodeBasicInfo = nodeInfo + i;
        uint8_t mUdid[UDID_BUF_LEN] = {0};
        if (GetNodeKeyInfo(DM_PKG_NAME, reinterpret_cast<char *>(nodeBasicInfo->networkId),
            NodeDeviceInfoKey::NODE_KEY_UDID, mUdid, sizeof(mUdid)) != DM_OK) {
            LOGE("[SOFTBUS]GetNodeKeyInfo failed.");
        }
        if (reinterpret_cast<char *>(mUdid) == deviceId) {
            FreeNodeInfo(nodeInfo);
            return static_cast<std::string>(nodeBasicInfo->networkId);
        }
    }
    FreeNodeInfo(nodeInfo);
    return "";
}

void SoftbusConnector::SetProcessInfo(ProcessInfo processInfo)
{
    LOGI("SoftbusConnector::SetProcessInfo");
    std::lock_guard<std::mutex> lock(processInfoVecMutex_);
    processInfoVec_.push_back(processInfo);
}

void SoftbusConnector::SetProcessInfoVec(std::vector<ProcessInfo> processInfoVec)
{
    LOGI("SoftbusConnector::SetProcessInfoVec");
    std::lock_guard<std::mutex> lock(processInfoVecMutex_);
    processInfoVec_ = processInfoVec;
}

std::vector<ProcessInfo> SoftbusConnector::GetProcessInfo()
{
    LOGI("In");
    std::lock_guard<std::mutex> lock(processInfoVecMutex_);
    return processInfoVec_;
}

void SoftbusConnector::ClearProcessInfo()
{
    LOGI("In");
    std::lock_guard<std::mutex> lock(processInfoVecMutex_);
    processInfoVec_.clear();
}

void SoftbusConnector::HandleDeviceOnline(std::string deviceId, int32_t authForm)
{
    LOGI("SoftbusConnector::HandleDeviceOnline");
    deviceStateManagerCallback_->OnDeviceOnline(deviceId, authForm);
    return;
}

void SoftbusConnector::HandleDeviceOffline(std::string deviceId)
{
    LOGI("SoftbusConnector::HandleDeviceOffline");
    deviceStateManagerCallback_->OnDeviceOffline(deviceId);
    return;
}

void SoftbusConnector::DeleteOffLineTimer(std::string &udidHash)
{
    LOGI("SoftbusConnector::DeleteOffLineTimer");
    remoteUdidHash_ = udidHash;
    if (deviceStateManagerCallback_ != nullptr) {
        deviceStateManagerCallback_->DeleteOffLineTimer(udidHash);
    }
}

bool SoftbusConnector::CheckIsOnline(const std::string &targetDeviceId)
{
    LOGI("Check the device is online.");
    int32_t deviceCount = 0;
    NodeBasicInfo *nodeInfo = nullptr;
    if (GetAllNodeDeviceInfo(DM_PKG_NAME, &nodeInfo, &deviceCount) != DM_OK) {
        LOGE("[SOFTBUS]GetAllNodeDeviceInfo failed.");
        return false;
    }
    for (int32_t i = 0; i < deviceCount; ++i) {
        NodeBasicInfo *nodeBasicInfo = nodeInfo + i;
        uint8_t mUdid[UDID_BUF_LEN] = {0};
        if (GetNodeKeyInfo(DM_PKG_NAME, reinterpret_cast<char *>(nodeBasicInfo->networkId),
            NodeDeviceInfoKey::NODE_KEY_UDID, mUdid, sizeof(mUdid)) != DM_OK) {
            LOGE("[SOFTBUS]GetNodeKeyInfo failed.");
        }
        std::string udid = reinterpret_cast<char *>(mUdid);
        if (udid == targetDeviceId) {
            LOGI("The device is online.");
            FreeNodeInfo(nodeInfo);
            return true;
        }
    }
    LOGI("The device is not online.");
    FreeNodeInfo(nodeInfo);
    return false;
}

DmDeviceInfo SoftbusConnector::GetDeviceInfoByDeviceId(const std::string &deviceId)
{
    LOGI("SoftbusConnector::GetDeviceInfoBydeviceId");
    DmDeviceInfo info;
    int32_t deviceCount = 0;
    NodeBasicInfo *nodeInfo = nullptr;
    if (GetAllNodeDeviceInfo(DM_PKG_NAME, &nodeInfo, &deviceCount) != DM_OK) {
        LOGE("[SOFTBUS]GetAllNodeDeviceInfo failed.");
        return info;
    }
    char deviceIdHash[DM_MAX_DEVICE_ID_LEN] = {0};
    if (Crypto::GetUdidHash(deviceId, reinterpret_cast<uint8_t *>(deviceIdHash)) != DM_OK) {
        LOGE("get deviceIdHash by deviceId: %{public}s failed.", GetAnonyString(deviceId).c_str());
        FreeNodeInfo(nodeInfo);
        return info;
    }
    for (int32_t i = 0; i < deviceCount; ++i) {
        NodeBasicInfo *nodeBasicInfo = nodeInfo + i;
        uint8_t mUdid[UDID_BUF_LEN] = {0};
        if (GetNodeKeyInfo(DM_PKG_NAME, nodeBasicInfo->networkId, NodeDeviceInfoKey::NODE_KEY_UDID,
            mUdid, sizeof(mUdid)) != DM_OK) {
            LOGE("[SOFTBUS]GetNodeKeyInfo failed.");
            FreeNodeInfo(nodeInfo);
            return info;
        }
        std::string udid = reinterpret_cast<char *>(mUdid);
        if (udid != deviceId) {
            continue;
        } else {
            ConvertNodeBasicInfoToDmDevice(*nodeBasicInfo, info);
            if (memcpy_s(info.deviceId, DM_MAX_DEVICE_ID_LEN, deviceIdHash, DM_MAX_DEVICE_ID_LEN) != 0) {
                LOGE("Get deviceId: %{public}s failed.", GetAnonyString(deviceId).c_str());
            }
            break;
        }
    }
    FreeNodeInfo(nodeInfo);
    return info;
}

void SoftbusConnector::ConvertNodeBasicInfoToDmDevice(const NodeBasicInfo &nodeBasicInfo, DmDeviceInfo &dmDeviceInfo)
{
    if (memset_s(&dmDeviceInfo, sizeof(DmDeviceInfo), 0, sizeof(DmDeviceInfo)) != EOK) {
        LOGE("ConvertNodeBasicInfoToDmDevice memset_s failed.");
        return;
    }

    if (memcpy_s(dmDeviceInfo.networkId, sizeof(dmDeviceInfo.networkId), nodeBasicInfo.networkId,
                 std::min(sizeof(dmDeviceInfo.networkId), sizeof(nodeBasicInfo.networkId))) != EOK) {
        LOGE("ConvertNodeBasicInfoToDmDevice copy deviceId data failed.");
        return;
    }

    if (memcpy_s(dmDeviceInfo.deviceName, sizeof(dmDeviceInfo.deviceName), nodeBasicInfo.deviceName,
                 std::min(sizeof(dmDeviceInfo.deviceName), sizeof(nodeBasicInfo.deviceName))) != EOK) {
        LOGE("ConvertDeviceInfoToDmDevice copy deviceName data failed.");
        return;
    }

    dmDeviceInfo.deviceTypeId = nodeBasicInfo.deviceTypeId;
    std::string extraData = dmDeviceInfo.extraData;
    nlohmann::json extraJson;
    if (!extraData.empty()) {
        extraJson = nlohmann::json::parse(extraData, nullptr, false);
    }
    if (!extraJson.is_discarded()) {
        extraJson[PARAM_KEY_OS_TYPE] = nodeBasicInfo.osType;
        extraJson[PARAM_KEY_OS_VERSION] = std::string(nodeBasicInfo.osVersion);
        dmDeviceInfo.extraData = to_string(extraJson);
    }
}
} // namespace DistributedHardware
} // namespace OHOS
