/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "softbus_connector_refactor.h"

#include <algorithm>
#include <securec.h>
#include <unistd.h>

#include "dm_anonymous.h"
#include "dm_constants.h"
#include "dm_crypto.h"
#include "dm_device_info.h"
#include "dm_log.h"
#include "dm_radar_helper.h"
#include "dm_softbus_cache.h"
#include "json_object.h"
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
constexpr const char* NCM_IP = "NCM_IP";
constexpr const char* NCM_PORT = "NCM_PORT";
constexpr const char* FILED_AUTHORIZED_APP_LIST = "authorizedAppList";

namespace {
    const char* TAG_ACL = "accessControlTable";
    const char* TAG_DMVERSION = "dmVersion";
}

std::string SoftbusConnector::remoteUdidHash_ = "";
std::map<std::string, std::shared_ptr<DeviceInfo>>
    SoftbusConnector::discoveryDeviceInfoMap_ = {};
std::unordered_map<std::string, std::string>
    SoftbusConnector::deviceUdidMap_ = {};
std::vector<ProcessInfo> SoftbusConnector::processInfoVec_ = {};
std::vector<ProcessInfo>
    SoftbusConnector::processChangeInfoVec_ = {};
std::mutex SoftbusConnector::discoveryDeviceInfoMutex_;
std::mutex SoftbusConnector::deviceUdidLocks_;
std::mutex SoftbusConnector::processInfoVecMutex_;
std::mutex SoftbusConnector::processChangeInfoVecMutex_;
std::shared_ptr<ISoftbusConnectorCallback>
    SoftbusConnector::connectorCallback_ = nullptr;
std::shared_ptr<ISoftbusLeaveLNNCallback>
    SoftbusConnector::leaveLNNCallback_ = nullptr;
std::mutex SoftbusConnector::leaveLNNMutex_;
std::map<std::string, std::string>
    SoftbusConnector::leaveLnnPkgMap_ = {};
std::mutex SoftbusConnector::dmDelInfoMutex_;
std::set<DelInfoCache> SoftbusConnector::dmDelInfoCache_ = {};

SoftbusConnector::SoftbusConnector()
{
    softbusSession_ = std::make_shared<SoftbusSession>();
    hiChainAuthConnector_ = std::make_shared<HiChainAuthConnector>();
    LOGD("constructor.");
}

SoftbusConnector::~SoftbusConnector()
{
    LOGD("destructor.");
}

void SoftbusConnector::RemoveTokenIdFromAppList(
    std::vector<std::string> &appList, const std::string &tokenId)
{
    auto it = std::find(appList.begin(), appList.end(), tokenId);
    if (it != appList.end()) {
        appList.erase(it);
    }
}

void SoftbusConnector::DeleteCredential(const DelInfoCache &acl)
{
    CHECK_NULL_VOID(hiChainAuthConnector_);
    JsonObject credJson;
    int32_t ret = hiChainAuthConnector_->QueryCredInfoByCredId(
        acl.userId, acl.credId, credJson);
    if (ret != DM_OK || !credJson.Contains(acl.credId)) {
        LOGE("err, ret:%{public}d", ret);
        return;
    }
    if (!credJson[acl.credId].Contains(FILED_AUTHORIZED_APP_LIST)) {
        ret = hiChainAuthConnector_->DeleteCredential(
            acl.userId, acl.credId);
        if (ret != DM_OK) {
            LOGE("DeletecredId err, ret:%{public}d", ret);
        }
        return;
    }
    auto profile = DeviceProfileConnector::GetInstance().
        GetAccessControlProfileByAccessControlId(acl.aclId);
    if (profile.GetAccessControlId() != acl.aclId) {
        LOGE("no found profile");
        return;
    }
    std::vector<std::string> appList;
    credJson[acl.credId][FILED_AUTHORIZED_APP_LIST].Get(appList);
    RemoveTokenIdFromAppList(appList,
        std::to_string(profile.GetAccesser().GetAccesserTokenId()));
    RemoveTokenIdFromAppList(appList,
        std::to_string(profile.GetAccessee().GetAccesseeTokenId()));
    if (appList.empty()) {
        ret = hiChainAuthConnector_->DeleteCredential(
            acl.userId, acl.credId);
        if (ret != DM_OK) {
            LOGE("DeletecredId err, ret:%{public}d", ret);
        }
        return;
    }
    hiChainAuthConnector_->UpdateCredential(
        acl.credId, acl.userId, appList);
}

bool SoftbusConnector::CheckAclInDeleteCache(const int32_t aclId)
{
    std::lock_guard<std::mutex> lock(dmDelInfoMutex_);
    for (const auto &item : dmDelInfoCache_) {
        if (item.aclId == aclId) {
            return true;
        }
    }
    return false;
}

void SoftbusConnector::SyncAclList()
{
    std::lock_guard<std::mutex> lock(dmDelInfoMutex_);
    for (const auto &item : dmDelInfoCache_) {
        int32_t userId = item.userId;
        int32_t sessionKeyId = item.sessionKeyId;
        int32_t aclId = item.aclId;
        std::string credId = item.credId;
        LOGI("userId:%{public}d, credId:%{public}s, "
            "sessionKeyId:%{public}d, aclId:%{public}d",
            userId, credId.c_str(), sessionKeyId, aclId);
        int32_t ret = DeviceProfileConnector::GetInstance().
            DeleteSessionKey(userId, sessionKeyId);
        if (ret != DM_OK) {
            LOGE("DeleteSessionKey failed. ret:%{public}d.", ret);
        }
        DeleteCredential(item);
        DeviceProfileConnector::GetInstance().
            DeleteAccessControlById(aclId);
    }
    dmDelInfoCache_.clear();
}

void SoftbusConnector::SyncAclList(int32_t userId, std::string credId,
    int32_t sessionKeyId, int32_t aclId)
{
    LOGI("userId:%{public}d, credId:%{public}s, "
        "sessionKeyId:%{public}d, aclId:%{public}d",
        userId, credId.c_str(), sessionKeyId, aclId);
    int32_t ret = DeviceProfileConnector::GetInstance().
        DeleteSessionKey(userId, sessionKeyId);
    if (ret != DM_OK) {
        LOGE("DeleteSessionKey failed.");
    }
    DeleteCredential({ userId, sessionKeyId, aclId, credId });
    DeviceProfileConnector::GetInstance().DeleteAccessControlById(aclId);
}

int32_t SoftbusConnector::SyncLocalAclList5_1_0(
    const std::string localUdid, const std::string remoteUdid,
    DistributedDeviceProfile::AccessControlProfile &localAcl,
    std::vector<std::string> &acLStrList, bool isDelImmediately)
{
    bool res = DeviceProfileConnector::GetInstance().
        ChecksumAcl(localAcl, acLStrList);
    if (res) {
        return DM_OK;
    }
    if (localAcl.GetAccesser().GetAccesserDeviceId() == localUdid &&
        localAcl.GetAccessee().GetAccesseeDeviceId() == remoteUdid) {
        if (!isDelImmediately) {
            LOGI("SyncLocalAclListProcess Src.");
            std::lock_guard<std::mutex> lock(dmDelInfoMutex_);
            dmDelInfoCache_.insert({
                localAcl.GetAccesser().GetAccesserUserId(),
                localAcl.GetAccesser().GetAccesserSessionKeyId(),
                localAcl.GetAccessControlId(),
                localAcl.GetAccesser().GetAccesserCredentialIdStr()});
        } else {
            SyncAclList(
                localAcl.GetAccesser().GetAccesserUserId(),
                localAcl.GetAccesser().GetAccesserCredentialIdStr(),
                localAcl.GetAccesser().GetAccesserSessionKeyId(),
                localAcl.GetAccessControlId());
        }
    }
    if (localAcl.GetAccesser().GetAccesserDeviceId() == remoteUdid &&
        localAcl.GetAccessee().GetAccesseeDeviceId() == localUdid) {
        if (!isDelImmediately) {
            LOGI("SyncLocalAclListProcess Sink.");
            std::lock_guard<std::mutex> lock(dmDelInfoMutex_);
            dmDelInfoCache_.insert({
                localAcl.GetAccessee().GetAccesseeUserId(),
                localAcl.GetAccessee().GetAccesseeSessionKeyId(),
                localAcl.GetAccessControlId(),
                localAcl.GetAccessee().GetAccesseeCredentialIdStr()});
        } else {
            SyncAclList(
                localAcl.GetAccessee().GetAccesseeUserId(),
                localAcl.GetAccessee().GetAccesseeCredentialIdStr(),
                localAcl.GetAccessee().GetAccesseeSessionKeyId(),
                localAcl.GetAccessControlId());
        }
    }
    return DM_OK;
}

int32_t SoftbusConnector::ParaseAclChecksumList(
    const std::string &jsonString,
    std::vector<AclHashItem> &remoteAllAclList)
{
    JsonObject aclChecksumjson(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
    aclChecksumjson.Parse(jsonString);
    if (aclChecksumjson.IsDiscarded()) {
        LOGE("ParseSyncMessage aclChecksumjson error");
        return ERR_DM_FAILED;
    }
    DeviceProfileConnector::GetInstance().
        AclHashVecFromJson(aclChecksumjson, remoteAllAclList);
    return DM_OK;
}

int32_t SoftbusConnector::GetLocalVersion(
    const std::string localUdid, const std::string remoteUdid,
    std::string &localVersion,
    DistributedDeviceProfile::AccessControlProfile &localAcl)
{
    if (localAcl.GetAccesser().GetAccesserDeviceId() == localUdid &&
        localAcl.GetAccessee().GetAccesseeDeviceId() == remoteUdid) {
        std::string extraInfo =
            localAcl.GetAccesser().GetAccesserExtraData();
        DeviceProfileConnector::GetInstance().
            GetVersionByExtra(extraInfo, localVersion);
    } else if (localAcl.GetAccesser().GetAccesserDeviceId() ==
        remoteUdid &&
        localAcl.GetAccessee().GetAccesseeDeviceId() == localUdid) {
        std::string extraInfo =
            localAcl.GetAccessee().GetAccesseeExtraData();
        DeviceProfileConnector::GetInstance().
            GetVersionByExtra(extraInfo, localVersion);
    }
    return DM_OK;
}

void SoftbusConnector::SortAclListDesc(
    const std::vector<AclHashItem> &remoteAllAclList,
    std::vector<std::string> &aclVerDesc,
    std::map<std::string, AclHashItem> &remoteAllAclMap)
{
    aclVerDesc.clear();
    remoteAllAclMap.clear();
    for (const auto &item : remoteAllAclList) {
        aclVerDesc.push_back(item.version);
        remoteAllAclMap[item.version] = item;
    }
    std::sort(aclVerDesc.begin(), aclVerDesc.end(),
        [](const std::string &a, const std::string &b) {
            return CompareVersion(a, b);
        });
}

std::string SoftbusConnector::MatchTargetVersion(
    const std::string &localVersion,
    const std::vector<std::string> &remoteVerDesc)
{
    if (remoteVerDesc.empty()) {
        return localVersion;
    }
    if (CompareVersion(localVersion, remoteVerDesc[0])) {
        return remoteVerDesc[0];
    }
    return localVersion;
}

int32_t SoftbusConnector::SyncLocalAclListProcess(
    const DevUserInfo &localDevUserInfo,
    const DevUserInfo &remoteDevUserInfo,
    std::string remoteAclList, bool isDelImmediately)
{
    std::vector<AclHashItem> remoteAllAclList;
    int32_t ret = ParaseAclChecksumList(remoteAclList,
        remoteAllAclList);
    if (ret != DM_OK) {
        LOGE("TAG_ACL error");
        return ret;
    }
    std::vector<std::string> aclVerDesc;
    std::map<std::string, AclHashItem> remoteAllAclMap;
    SortAclListDesc(remoteAllAclList, aclVerDesc, remoteAllAclMap);
    std::string matchVersion = MatchTargetVersion(
        DM_ACL_AGING_VERSION, aclVerDesc);
    std::vector<std::string> remoteAclHashList;
    if (remoteAllAclMap.find(matchVersion) !=
        remoteAllAclMap.end()) {
        remoteAclHashList = remoteAllAclMap[matchVersion].aclHashList;
    }
    auto localAclList = DeviceProfileConnector::GetInstance().
        GetAclList(localDevUserInfo.deviceId,
            localDevUserInfo.userId,
            remoteDevUserInfo.deviceId,
            remoteDevUserInfo.userId);
    for (auto &localAcl : localAclList) {
        int32_t versionNum = 0;
        if (!GetVersionNumber(matchVersion, versionNum)) {
            LOGE("SyncLocalAclList GetVersionNumber error");
            continue;
        }
        if (versionNum == DM_VERSION_INT_5_1_0) {
            SyncLocalAclList5_1_0(localDevUserInfo.deviceId,
                remoteDevUserInfo.deviceId, localAcl,
                remoteAclHashList, isDelImmediately);
        } else {
            LOGE("versionNum is invaild, ver: %{public}d",
                versionNum);
        }
    }
    return DM_OK;
}

int32_t SoftbusConnector::GetAclListHash(
    const DevUserInfo &localDevUserInfo,
    const DevUserInfo &remoteDevUserInfo, std::string &aclList)
{
    return DeviceProfileConnector::GetInstance().
        GetAclListHashStr(localDevUserInfo, remoteDevUserInfo,
            aclList);
}

int32_t SoftbusConnector::RegisterConnectorCallback(
    std::shared_ptr<ISoftbusConnectorCallback> callback)
{
    connectorCallback_ = callback;
    return DM_OK;
}

int32_t SoftbusConnector::UnRegisterConnectorCallback()
{
    connectorCallback_ = nullptr;
    return DM_OK;
}

int32_t SoftbusConnector::RegisterSoftbusStateCallback(
    const std::shared_ptr<ISoftbusStateCallback> callback)
{
    deviceStateManagerCallback_ = callback;
    return DM_OK;
}

int32_t SoftbusConnector::UnRegisterSoftbusStateCallback()
{
    deviceStateManagerCallback_ = nullptr;
    return DM_OK;
}

bool SoftbusConnector::ConvertBleUdidHash(
    ConnectionAddr *addrInfo, const std::string &udidHash)
{
    if (addrInfo == nullptr) {
        return false;
    }
    if (addrInfo->type != ConnectionAddrType::CONNECTION_ADDR_BLE) {
        return true;
    }
    if (Crypto::ConvertHexStringToBytes(addrInfo->info.ble.udidHash,
        UDID_HASH_LEN, udidHash.c_str(),
        udidHash.length()) != DM_OK) {
        LOGE("convert remoteUdid hash failed, "
            "udidHash: %{public}s.",
            GetAnonyString(udidHash).c_str());
        return false;
    }
    return true;
}

void SoftbusConnector::DoJoinLnn(const std::string &deviceId,
    const std::string &udidHash, bool isForceJoin)
{
    std::string connectAddr;
    auto addrInfo = GetConnectAddr(deviceId, connectAddr);
    if (addrInfo == nullptr) {
        LOGE("addrInfo is nullptr.");
        return;
    }
    if (!ConvertBleUdidHash(addrInfo.get(), udidHash)) {
        return;
    }
    int32_t ret = ::JoinLNN(DM_PKG_NAME, addrInfo.get(),
        OnSoftbusJoinLNNResult, isForceJoin);
    if (ret != DM_OK) {
        LOGE("[SOFTBUS]JoinLNN failed, ret: %{public}d.", ret);
    }
}

void SoftbusConnector::JoinLnn(const std::string &deviceId,
    bool isForceJoin)
{
    LOGI("start, deviceId: %{public}s.",
        GetAnonyString(deviceId).c_str());
    DoJoinLnn(deviceId, remoteUdidHash_, isForceJoin);
}

void SoftbusConnector::JoinLnn(const std::string &deviceId,
    const std::string &remoteUdidHash)
{
    LOGI("start, deviceId: %{public}s.",
        GetAnonyString(deviceId).c_str());
    DoJoinLnn(deviceId, remoteUdidHash, false);
}

void SoftbusConnector::JoinLNNBySkId(int32_t sessionId,
    int32_t sessionKeyId, int32_t remoteSessionKeyId,
    std::string udid, std::string udidHash, bool isForceJoin)
{
    LOGI("start, JoinLNNBySkId sessionId: %{public}d, "
        "udid: %{public}s.", sessionId,
        GetAnonyString(udid).c_str());
    std::string connectAddr;
    auto addrInfo = GetConnectAddr(udid, connectAddr);
    if (addrInfo == nullptr) {
        LOGE("addrInfo is nullptr.");
        return;
    }
    if (!ConvertBleUdidHash(addrInfo.get(), udidHash)) {
        return;
    }
    if (sessionKeyId > 0 && remoteSessionKeyId > 0) {
        addrInfo->deviceKeyId.hasDeviceKeyId = true;
        addrInfo->deviceKeyId.localDeviceKeyId = sessionKeyId;
        addrInfo->deviceKeyId.remoteDeviceKeyId = remoteSessionKeyId;
    } else {
        addrInfo->deviceKeyId.hasDeviceKeyId = false;
        addrInfo->deviceKeyId.localDeviceKeyId = 0;
        addrInfo->deviceKeyId.remoteDeviceKeyId = 0;
    }
    int32_t ret = ::JoinLNN(DM_PKG_NAME, addrInfo.get(),
        OnSoftbusJoinLNNResult, isForceJoin);
    if (ret != DM_OK) {
        LOGE("[SOFTBUS]JoinLNNBySkId failed, ret: %{public}d.", ret);
    }
}

void SoftbusConnector::JoinLnnByHml(int32_t sessionId,
    int32_t sessionKeyId, int32_t remoteSessionKeyId,
    bool isForceJoin)
{
    LOGI("start, JoinLnnByHml sessionId: %{public}d.", sessionId);
    ConnectionAddr addrInfo;
    addrInfo.type = CONNECTION_ADDR_SESSION_WITH_KEY;
    addrInfo.info.session.sessionId = sessionId;
    addrInfo.deviceKeyId.hasDeviceKeyId = true;
    if (sessionKeyId > 0 && remoteSessionKeyId > 0) {
        addrInfo.deviceKeyId.localDeviceKeyId = sessionKeyId;
        addrInfo.deviceKeyId.remoteDeviceKeyId = remoteSessionKeyId;
        LOGI("sessionKeyId valid");
    } else {
        addrInfo.deviceKeyId.localDeviceKeyId = 0;
        addrInfo.deviceKeyId.remoteDeviceKeyId = 0;
    }
    int32_t ret = ::JoinLNN(DM_PKG_NAME, &addrInfo,
        OnSoftbusJoinLNNResult, isForceJoin);
    if (ret != DM_OK) {
        LOGE("[SOFTBUS]JoinLNN failed, ret: %{public}d.", ret);
    }
}

int32_t SoftbusConnector::GetUdidByNetworkId(const char *networkId,
    std::string &udid)
{
    if (networkId == nullptr) {
        LOGE("networkId is nullptr.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    LOGI("start, networkId: %{public}s.",
        GetAnonyString(std::string(networkId)).c_str());
    return SoftbusCache::GetInstance().GetUdidFromCache(
        networkId, udid);
}

int32_t SoftbusConnector::GetUuidByNetworkId(const char *networkId,
    std::string &uuid)
{
    if (networkId == nullptr) {
        LOGE("networkId is nullptr.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    LOGI("start, networkId: %{public}s.",
        GetAnonyString(std::string(networkId)).c_str());
    return SoftbusCache::GetInstance().GetUuidFromCache(
        networkId, uuid);
}

std::shared_ptr<SoftbusSession> SoftbusConnector::GetSoftbusSession()
{
    return softbusSession_;
}

bool SoftbusConnector::HaveDeviceInMap(std::string deviceId)
{
    std::lock_guard<std::mutex> lock(discoveryDeviceInfoMutex_);
    auto iter = discoveryDeviceInfoMap_.find(deviceId);
    if (iter == discoveryDeviceInfoMap_.end()) {
        LOGE("deviceInfo not found by deviceId: %{public}s.",
            GetAnonyString(deviceId).c_str());
        return false;
    }
    return true;
}

ConnectionAddr *SoftbusConnector::GetConnectAddrByType(
    DeviceInfo *deviceInfo, ConnectionAddrType type)
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

std::shared_ptr<DeviceInfo>
    SoftbusConnector::GetDeviceInfoFromMap(const std::string &deviceId)
{
    std::lock_guard<std::mutex> lock(discoveryDeviceInfoMutex_);
    auto iter = discoveryDeviceInfoMap_.find(deviceId);
    if (iter == discoveryDeviceInfoMap_.end()) {
        LOGE("deviceInfo not found by deviceId: %{public}s.",
            GetAnonyString(deviceId).c_str());
        return nullptr;
    }
    return iter->second;
}

std::shared_ptr<ConnectionAddr> SoftbusConnector::SetAddrAndJson(
    const ConnectionAddr *addr, JsonObject &jsonPara,
    std::string &connectAddr)
{
    if (addr == nullptr) {
        LOGE("Param not valid, addr is null.");
        return nullptr;
    }
    auto connectAddrPtr = std::make_shared<ConnectionAddr>();
    *connectAddrPtr = *addr;
    connectAddr = jsonPara.Dump();
    return connectAddrPtr;
}

std::shared_ptr<ConnectionAddr> SoftbusConnector::TryGetAddr(
    DeviceInfo *deviceInfo, ConnectionAddrType type,
    JsonObject &jsonPara, std::string &connectAddr)
{
    ConnectionAddr *addr = GetConnectAddrByType(deviceInfo, type);
    if (addr == nullptr) {
        return nullptr;
    }
    switch (type) {
        case CONNECTION_ADDR_ETH:
            jsonPara[ETH_IP] = addr->info.ip.ip;
            jsonPara[ETH_PORT] = addr->info.ip.port;
            break;
        case CONNECTION_ADDR_WLAN:
            jsonPara[WIFI_IP] = addr->info.ip.ip;
            jsonPara[WIFI_PORT] = addr->info.ip.port;
            break;
        case CONNECTION_ADDR_BR:
            jsonPara[BR_MAC] = addr->info.br.brMac;
            break;
        case CONNECTION_ADDR_BLE:
            jsonPara[BLE_MAC] = addr->info.ble.bleMac;
            addr->info.ble.priority = BLE_PRIORITY_HIGH;
            break;
        case CONNECTION_ADDR_NCM:
            jsonPara[NCM_IP] = addr->info.ip.ip;
            jsonPara[NCM_PORT] = addr->info.ip.port;
            break;
        default:
            return nullptr;
    }
    return SetAddrAndJson(addr, jsonPara, connectAddr);
}

std::shared_ptr<ConnectionAddr> SoftbusConnector::GetConnectAddr(
    const std::string &deviceId, std::string &connectAddr)
{
    auto deviceInfo = GetDeviceInfoFromMap(deviceId);
    if (deviceInfo == nullptr || deviceInfo->addrNum <= 0 ||
        deviceInfo->addrNum >= CONNECTION_ADDR_MAX) {
        LOGE("deviceInfo addrNum not valid, addrNum: %{public}d.",
            (deviceInfo != nullptr) ? deviceInfo->addrNum : 0);
        return nullptr;
    }
    ConnectionAddrType types[] = {
        CONNECTION_ADDR_ETH,
        CONNECTION_ADDR_WLAN,
        CONNECTION_ADDR_BR,
        CONNECTION_ADDR_BLE,
        CONNECTION_ADDR_NCM,
    };
    JsonObject jsonPara;
    for (auto type : types) {
        auto addr = TryGetAddr(deviceInfo.get(), type,
            jsonPara, connectAddr);
        if (addr != nullptr) {
            return addr;
        }
    }
    LOGE("[SOFTBUS]failed to get ConnectionAddr for "
        "deviceId: %{public}s.",
        GetAnonyString(deviceId).c_str());
    return nullptr;
}

void SoftbusConnector::ConvertDeviceInfoToDmDevice(
    const DeviceInfo &deviceInfo, DmDeviceInfo &dmDeviceInfo)
{
    if (memset_s(&dmDeviceInfo, sizeof(DmDeviceInfo), 0,
        sizeof(DmDeviceInfo)) != EOK) {
        LOGE("memset_s failed.");
        return;
    }
    if (memcpy_s(dmDeviceInfo.deviceId,
        sizeof(dmDeviceInfo.deviceId), deviceInfo.devId,
        std::min(sizeof(dmDeviceInfo.deviceId),
            sizeof(deviceInfo.devId))) != EOK) {
        LOGE("copy deviceId data failed.");
        return;
    }
    if (memcpy_s(dmDeviceInfo.deviceName,
        sizeof(dmDeviceInfo.deviceName), deviceInfo.devName,
        std::min(sizeof(dmDeviceInfo.deviceName),
            sizeof(deviceInfo.devName))) != EOK) {
        LOGE("copy deviceName data failed.");
        return;
    }
    dmDeviceInfo.deviceTypeId = deviceInfo.devType;
    dmDeviceInfo.range = deviceInfo.range;
}

void SoftbusConnector::ConvertDeviceInfoToDmDevice(
    const DeviceInfo &deviceInfo,
    DmDeviceBasicInfo &dmDeviceBasicInfo)
{
    if (memset_s(&dmDeviceBasicInfo, sizeof(DmDeviceBasicInfo),
        0, sizeof(DmDeviceBasicInfo)) != EOK) {
        LOGE("memset_s failed.");
        return;
    }
    if (memcpy_s(dmDeviceBasicInfo.deviceId,
        sizeof(dmDeviceBasicInfo.deviceId), deviceInfo.devId,
        std::min(sizeof(dmDeviceBasicInfo.deviceId),
            sizeof(deviceInfo.devId))) != EOK) {
        LOGE("copy deviceId data failed.");
        return;
    }
    if (memcpy_s(dmDeviceBasicInfo.deviceName,
        sizeof(dmDeviceBasicInfo.deviceName), deviceInfo.devName,
        std::min(sizeof(dmDeviceBasicInfo.deviceName),
            sizeof(deviceInfo.devName))) != EOK) {
        LOGE("copy deviceName data failed.");
        return;
    }
    dmDeviceBasicInfo.deviceTypeId = deviceInfo.devType;
}

void SoftbusConnector::OnSoftbusJoinLNNResult(ConnectionAddr *addr,
    const char *networkId, int32_t result)
{
    LOGI("[SOFTBUS]OnSoftbusJoinLNNResult, result: %{public}d.",
        result);
    if (addr == nullptr) {
        LOGE("addr is null.");
        return;
    }
    if (addr->type != CONNECTION_ADDR_SESSION_WITH_KEY) {
        LOGI("addr type is not session.");
        return;
    }
    int32_t sessionId = addr->info.session.sessionId;
    CHECK_NULL_VOID(connectorCallback_);
    connectorCallback_->OnSoftbusJoinLNNResult(sessionId,
        networkId, result);
}

std::string SoftbusConnector::GetDeviceUdidByUdidHash(
    const std::string &udidHash)
{
    std::lock_guard<std::mutex> lock(deviceUdidLocks_);
    for (auto &iter : deviceUdidMap_) {
        if (iter.second == udidHash) {
            return iter.first;
        }
    }
    LOGE("fail to GetUdidByUdidHash, "
        "udidHash: %{public}s",
        GetAnonyString(udidHash).c_str());
    return udidHash;
}

std::string SoftbusConnector::GetDeviceUdidHashByUdid(
    const std::string &udid)
{
    {
        std::lock_guard<std::mutex> lock(deviceUdidLocks_);
        auto iter = deviceUdidMap_.find(udid);
        if (iter != deviceUdidMap_.end()) {
            return iter->second;
        }
    }
    char udidHash[DM_MAX_DEVICE_ID_LEN] = {0};
    if (Crypto::GetUdidHash(udid,
        reinterpret_cast<uint8_t *>(udidHash)) != DM_OK) {
        LOGE("get udidhash by udid: %{public}s failed.",
            GetAnonyString(udid).c_str());
        return "";
    }
    LOGI("get udidhash: %{public}s by udid: %{public}s.",
        GetAnonyString(udidHash).c_str(),
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
    if (deviceUdidMap_.size() >=
        SOFTBUS_TRUSTDEVICE_UUIDHASH_INFO_MAX_SIZE) {
        deviceUdidMap_.erase(udid);
    }
}
} // namespace DistributedHardware
} // namespace OHOS