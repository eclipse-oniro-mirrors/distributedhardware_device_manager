/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "softbus_adapter.h"

#include <cstdlib>
#include <set>
#include <string>
#include <unistd.h>

#include <securec.h>

#include "dm_device_info.h"

#include "anonymous_string.h"
#include "device_manager_errno.h"
#include "device_manager_log.h"
#include "device_manager_service.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
const std::string DEVICE_MANAGER_PACKAGE_NAME = "ohos.distributedhardware.devicemanager";
const int32_t CHECK_INTERVAL = 100000; // 100ms
const int32_t SUBSCRIBE_ID_PREFIX_LEN = 16;
const int32_t SUBSCRIBE_ID_MASK = 0x0000FFFF;
const int32_t DISCOVER_DEVICEINFO_MAX_SIZE = 20;
}

IMPLEMENT_SINGLE_INSTANCE(SoftbusAdapter);
void SoftbusAdapter::OnSoftBusDeviceOnline(NodeBasicInfo *info)
{
    if (info == nullptr) {
        HILOGE("SoftbusAdapter::OnSoftBusDeviceOnline NodeBasicInfo is nullptr");
        return;
    }

    std::string networkId = info->networkId;
    HILOGI("device online, networkId: %{public}s", GetAnonyString(networkId).c_str());
    OnSoftBusDeviceStateChange(DmDeviceState::DEVICE_STATE_ONLINE, info);

    uint8_t udid[UDID_BUF_LEN] = {0};
    int32_t ret = GetNodeKeyInfo(DEVICE_MANAGER_PACKAGE_NAME.c_str(), info->networkId,
        NodeDeivceInfoKey::NODE_KEY_UDID, udid, sizeof(udid));
    if (ret != ERR_OK) {
        HILOGE("GetNodeKeyInfo failed");
        return;
    }
    std::string deviceId = (char *)udid;
    SoftbusAdapter::GetInstance().RemoveDiscoverDeviceInfo(deviceId);
}

void SoftbusAdapter::OnSoftbusDeviceOffline(NodeBasicInfo *info)
{
    if (info == nullptr) {
        HILOGE("SoftbusAdapter::OnSoftbusDeviceOffline NodeBasicInfo is nullptr");
        return;
    }

    std::string networkId = info->networkId;
    HILOGI("device offline, networkId: %{public}s", GetAnonyString(networkId).c_str());
    OnSoftBusDeviceStateChange(DmDeviceState::DEVICE_STATE_OFFLINE, info);
}

void SoftbusAdapter::OnSoftBusDeviceStateChange(DmDeviceState state, NodeBasicInfo *info)
{
    DmDeviceInfo deviceInfo;
    deviceInfo.deviceId = info->networkId;
    deviceInfo.deviceName = info->deviceName;
    deviceInfo.deviceTypeId = (DMDeviceType)info->deviceTypeId;

    std::map<std::string, sptr<IRemoteObject>> listeners = DeviceManagerService::GetInstance().GetDmListener();
    for (auto iter : listeners) {
        auto packageName = iter.first;
        auto remote = iter.second;
        sptr<IDeviceManagerListener> dmListener = iface_cast<IDeviceManagerListener>(remote);
        if (state == DmDeviceState::DEVICE_STATE_ONLINE) {
            HILOGI("SoftbusAdapter::OnSoftBusDeviceStateChange listenr handle device online.");
            dmListener->OnDeviceOnline(packageName, deviceInfo);
        } else {
            HILOGI("SoftbusAdapter::OnSoftBusDeviceStateChange listenr handle device offline.");
            dmListener->OnDeviceOffline(packageName, deviceInfo);
        }
    }
}

void SoftbusAdapter::OnSoftbusDeviceInfoChanged(NodeBasicInfoType type, NodeBasicInfo *info)
{
    HILOGI("SoftbusAdapter::OnSoftbusDeviceInfoChanged.");
    // currently do nothing
    (void)type;
    (void)info;
}

void SoftbusAdapter::OnSoftbusDeviceFound(const DeviceInfo *device)
{
    if (device == nullptr) {
        HILOGE("deviceinfo is null");
        return;
    }

    std::string deviceId = device->devId;
    HILOGI("SoftbusAdapter::OnSoftbusDeviceFound device %{public}s found.", GetAnonyString(deviceId).c_str());
    if (IsDeviceOnLine(deviceId)) {
        return;
    }

    SoftbusAdapter::GetInstance().SaveDiscoverDeviceInfo(device);
    DmDeviceInfo deviceInfo;
    deviceInfo.deviceId = deviceId;
    deviceInfo.deviceName = device->devName;
    deviceInfo.deviceTypeId = (DMDeviceType)device->devType;

    // currently, only care ddmpCapability
    if (!((device->capabilityBitmap[0] >> DDMP_CAPABILITY_BITMAP) & 0x1)) {
        HILOGE("capBitmap Invalid, not contain ddmpCap");
        return;
    }

    auto subscribeInfos = SoftbusAdapter::GetInstance().GetsubscribeInfos();
    for (auto iter = subscribeInfos.begin(); iter != subscribeInfos.end(); iter++) {
        auto subInfovector = iter->second;
        for (auto vectorIter = subInfovector.begin(); vectorIter != subInfovector.end(); ++vectorIter) {
            auto info = vectorIter->get();
            HILOGI("subscribe info capability:%{public}s.", info->info.capability);
            if (strcmp(DM_CAPABILITY_DDMP.c_str(), info->info.capability) != 0) {
                HILOGE("subscribe info capability invalid.");
            }
            std::string packageName = iter->first;
            sptr<IDeviceManagerListener> listener = DeviceManagerService::GetInstance().GetDmListener(packageName);
            if (listener == nullptr) {
                HILOGI("cannot get listener for package:%{public}s.", packageName.c_str());
                continue;
            }

            uint16_t originId = (uint16_t)(((uint32_t)info->info.subscribeId) & SUBSCRIBE_ID_MASK);
            HILOGI("call OnDeviceFound for %{public}s, originId %{public}d, deviceId %{public}s",
                packageName.c_str(), originId, GetAnonyString(deviceInfo.deviceId).c_str());
            listener->OnDeviceFound(packageName, originId, deviceInfo);
        }
    }
}

void SoftbusAdapter::OnSoftbusDiscoverFailed(int subscribeId, DiscoveryFailReason failReason)
{
    HILOGI("In, subscribeId %{public}d, failReason %{public}d", subscribeId, (int32_t)failReason);
    std::string packageName;
    if (!SoftbusAdapter::GetInstance().GetPackageNameBySubscribeId(subscribeId, packageName)) {
        HILOGE("OnSoftbusDiscoverFailed: packageName not found");
        return;
    }
    sptr<IDeviceManagerListener> listener = DeviceManagerService::GetInstance().GetDmListener(packageName);
    if (listener == nullptr) {
        HILOGE("OnSoftbusDiscoverFailed: listener not found for packageName %{public}s", packageName.c_str());
        return;
    }
    uint16_t originId = (uint16_t)(((uint32_t)subscribeId) & SUBSCRIBE_ID_MASK);
    listener->OnDiscoverFailed(packageName, originId, (int32_t)failReason);
}

void SoftbusAdapter::OnSoftbusDiscoverySuccess(int subscribeId)
{
    HILOGI("In, subscribeId %{public}d", subscribeId);
    std::string packageName;
    if (!SoftbusAdapter::GetInstance().GetPackageNameBySubscribeId(subscribeId, packageName)) {
        HILOGE("OnSoftbusDiscoverySuccess: packageName not found");
        return;
    }
    sptr<IDeviceManagerListener> listener = DeviceManagerService::GetInstance().GetDmListener(packageName);
    if (listener == nullptr) {
        HILOGE("OnSoftbusDiscoverySuccess: listener not found for packageName %{public}s", packageName.c_str());
        return;
    }
    uint16_t originId = (uint16_t)(((uint32_t)subscribeId) & SUBSCRIBE_ID_MASK);
    listener->OnDiscoverySuccess(packageName, originId);
}

void SoftbusAdapter::OnSoftbusJoinLNNResult(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    (void)addr;
    if (retCode != 0) {
        HILOGE("OnSoftbusJoinLNNResult: failed, retCode %{public}d", retCode);
        return;
    }

    if (networkId == nullptr) {
        HILOGE("OnSoftbusJoinLNNResult: success, but networkId is nullptr");
        return;
    }

    std::string netIdStr = networkId;
    HILOGI("OnSoftbusJoinLNNResult: success, networkId %{public}s, retCode %{public}d",
        GetAnonyString(netIdStr).c_str(), retCode);
}

void SoftbusAdapter::OnSoftbusLeaveLNNResult(const char *networkId, int32_t retCode)
{
    if (retCode != 0) {
        HILOGE("OnSoftbusLeaveLNNResult: failed, retCode %{public}d", retCode);
        return;
    }

    if (networkId == nullptr) {
        HILOGE("OnSoftbusLeaveLNNResult: success, but networkId is nullptr");
        return;
    }

    std::string netIdStr = networkId;
    HILOGI("OnSoftbusLeaveLNNResult: success, networkId %{public}s, retCode %{public}d",
        GetAnonyString(netIdStr).c_str(), retCode);
}

int32_t SoftbusAdapter::GetSoftbusTrustDevices(const std::string &packageName, std::string &extra,
    std::vector<DmDeviceInfo> &deviceList)
{
    // extra not used yet
    (void) packageName;
    (void) extra;

    HILOGI("GetSoftbusTrustDevices start, packageName: %{public}s", packageName.c_str());
    NodeBasicInfo *info = nullptr;
    int32_t infoNum = 0;
    int32_t ret = GetAllNodeDeviceInfo(DEVICE_MANAGER_PACKAGE_NAME.c_str(), &info, &infoNum);
    if (ret != 0) {
        HILOGE("GetAllNodeDeviceInfo failed with ret %{public}d", ret);
        return ret;
    }

    for (int32_t i = 0; i < infoNum; i++) {
        NodeBasicInfo *nodeBasicInfo = info + i;
        if (nodeBasicInfo == nullptr) {
            HILOGE("nodeBasicInfo is empty for index %{public}d, infoNum %{public}d.", i, infoNum);
            continue;
        }
        DmDeviceInfo deviceInfo;
        deviceInfo.deviceId = nodeBasicInfo->networkId;
        deviceInfo.deviceName = nodeBasicInfo->deviceName;
        deviceInfo.deviceTypeId = (DMDeviceType)nodeBasicInfo->deviceTypeId;
        deviceList.push_back(deviceInfo);
    }
    FreeNodeInfo(info);
    HILOGI("success, packageName: %{public}s, deviceCount %{public}d", packageName.c_str(), deviceList.size());
    return ERR_OK;
}

bool SoftbusAdapter::IsDeviceOnLine(std::string &deviceId)
{
    std::vector<DmDeviceInfo> deviceList;
    std::string extra = "";
    if (GetSoftbusTrustDevices(DEVICE_MANAGER_PACKAGE_NAME, extra, deviceList) != ERR_OK) {
        HILOGE("SoftbusAdapter::IsDeviceOnLine GetSoftbusTrustDevices failed");
        return false;
    }

    for (auto iter = deviceList.begin(); iter != deviceList.end(); ++iter) {
        std::string& networkId = iter->deviceId;
        if (networkId == deviceId) {
            HILOGI("SoftbusAdapter::IsDeviceOnLine devccie %{public}s online", GetAnonyString(deviceId).c_str());
            return true;
        }

        uint8_t udid[UDID_BUF_LEN] = {0};
        int32_t ret = GetNodeKeyInfo(DEVICE_MANAGER_PACKAGE_NAME.c_str(), networkId.c_str(),
            NodeDeivceInfoKey::NODE_KEY_UDID, udid, sizeof(udid));
        if (ret != ERR_OK) {
            HILOGE("SoftbusAdapter::IsDeviceOnLine GetNodeKeyInfo failed");
            return false;
        }

        if (strcmp((char *)udid, deviceId.c_str()) == 0) {
            HILOGI("SoftbusAdapter::IsDeviceOnLine devccie %{public}s online", GetAnonyString(deviceId).c_str());
            return true;
        }
    }
    return false;
}

void SoftbusAdapter::RegSoftBusDeviceStateListener()
{
    int32_t ret;
    int32_t retryTimes = 0;
    do {
        ret = RegNodeDeviceStateCb(DEVICE_MANAGER_PACKAGE_NAME.c_str(), &softbusNodeStateCb);
        if (ret != ERR_OK) {
            ++retryTimes;
            HILOGE("RegNodeDeviceStateCb failed with ret %{public}d, retryTimes %{public}d", ret, retryTimes);
            usleep(CHECK_INTERVAL);
        }
    } while (ret != ERR_OK);
    HILOGI("RegNodeDeviceStateCb success.");
}

int32_t SoftbusAdapter::StartSoftbusDiscovery(std::string &packageName, DmSubscribeInfo &info)
{
    std::shared_ptr<SubscribeInfoAdapter> subinfo = nullptr;
    if (subscribeInfos_.find(packageName) == subscribeInfos_.end()) {
        subscribeInfos_[packageName] = {};
    }

    auto iter = subscribeInfos_.find(packageName);
    std::vector<std::shared_ptr<SubscribeInfoAdapter>> &subinfoVector = iter->second;
    auto vectorIter = subinfoVector.begin();
    for (; vectorIter != subinfoVector.end(); ++vectorIter) {
        if (vectorIter->get()->subscribeIdOrigin == info.subscribeId) {
            subinfo = *vectorIter;
            break;
        }
    }

    if (subinfo == nullptr) {
        subinfo = std::make_shared<SubscribeInfoAdapter>();
        subinfo->subscribeIdOrigin = info.subscribeId;
        subinfo->subscribeIdPrefix = subscribeIdPrefix++;
        subinfo->info.subscribeId = (subinfo->subscribeIdPrefix << SUBSCRIBE_ID_PREFIX_LEN) | info.subscribeId;
        subinfo->info.mode = (DiscoverMode)info.mode;
        subinfo->info.medium = (ExchanageMedium)info.medium;
        subinfo->info.freq = (ExchangeFreq)info.freq;
        subinfo->info.isSameAccount = info.isSameAccount;
        subinfo->info.isWakeRemote = info.isWakeRemote;
        subinfo->info.capability = info.capability.c_str();
        subinfo->info.capabilityData = nullptr;
        subinfo->info.dataLen = 0;
    }

    if (vectorIter == subinfoVector.end()) {
        subinfoVector.push_back(subinfo);
    }

    HILOGI("StartDiscovery, packageName: %{public}s, subscribeId %{public}d, prefix %{public}d, origin %{public}d",
        packageName.c_str(), subinfo->info.subscribeId, subinfo->subscribeIdPrefix, subinfo->subscribeIdOrigin);
    int ret = StartDiscovery(DEVICE_MANAGER_PACKAGE_NAME.c_str(), &subinfo->info, &softbusDiscoverCallback);
    if (ret != ERR_OK) {
        HILOGE("StartDiscovery failed with ret %{public}d.", ret);
    }
    return ret;
}

bool SoftbusAdapter::GetPackageNameBySubscribeId(int32_t adapterId, std::string &packageName)
{
    for (auto iter = subscribeInfos_.begin(); iter != subscribeInfos_.end(); ++iter) {
        std::vector<std::shared_ptr<SubscribeInfoAdapter>> &subinfoVector = iter->second;
        auto vectorIter = subinfoVector.begin();
        for (; vectorIter != subinfoVector.end(); ++vectorIter) {
            if (vectorIter->get()->info.subscribeId == adapterId) {
                packageName = iter->first;
                return true;
            }
        }
    }
    return false;
}

bool SoftbusAdapter::GetsubscribeIdAdapter(std::string packageName, int16_t originId, int32_t &adapterId)
{
    HILOGI("GetsubscribeIdAdapter in, packageName: %{public}s, originId:%{public}d", packageName.c_str(),
        (int32_t)originId);
    auto iter = subscribeInfos_.find(packageName);
    if (iter == subscribeInfos_.end()) {
        HILOGE("subscribeInfo not find for packageName: %{public}s", packageName.c_str());
        return false;
    }

    std::vector<std::shared_ptr<SubscribeInfoAdapter>> &subinfoVector = iter->second;
    auto vectorIter = subinfoVector.begin();
    for (; vectorIter != subinfoVector.end(); ++vectorIter) {
        if (vectorIter->get()->subscribeIdOrigin == originId) {
            HILOGE("find adapterId:%{public}d for packageName: %{public}s, originId:%{public}d",
                vectorIter->get()->info.subscribeId, packageName.c_str(), (int32_t)originId);
            adapterId = vectorIter->get()->info.subscribeId;
            return true;
        }
    }
    HILOGE("subscribe not find. packageName: %{public}s, originId:%{public}d", packageName.c_str(), (int32_t)originId);
    return false;
}

int32_t SoftbusAdapter::StopSoftbusDiscovery(std::string &packageName, uint16_t subscribeId)
{
    int32_t subscribeIdAdapter = -1;
    if (!GetsubscribeIdAdapter(packageName, subscribeId, subscribeIdAdapter)) {
        HILOGE("StopDiscovery failed, subscribeId not match");
        return ERR_INVALID_OPERATION;
    }

    HILOGI("StopDiscovery begin, packageName: %{public}s, subscribeId:%{public}d, subscribeIdAdapter:%{public}d",
        packageName.c_str(), (int32_t)subscribeId, subscribeIdAdapter);
    int ret = StopDiscovery(DEVICE_MANAGER_PACKAGE_NAME.c_str(), subscribeIdAdapter);
    if (ret != ERR_OK) {
        HILOGE("StopDiscovery failed with ret %{public}d", ret);
        return ret;
    }

    auto iter = subscribeInfos_.find(packageName);
    auto subinfoVector = iter->second;
    auto vectorIter = subinfoVector.begin();
    while (vectorIter != subinfoVector.end()) {
        if (vectorIter->get()->subscribeIdOrigin == subscribeId) {
            vectorIter = subinfoVector.erase(vectorIter);
            break;
        } else {
            ++vectorIter;
        }
    }
    if (subinfoVector.empty()) {
        subscribeInfos_.erase(packageName);
    }
    HILOGI("SoftbusAdapter::StopSoftbusDiscovery completed, packageName: %{public}s", packageName.c_str());
    return ERR_OK;
}

int32_t SoftbusAdapter::SoftbusJoinLnn(std::string devId)
{
    auto iter = discoverDeviceInfoMap_.find(devId);
    if (iter == discoverDeviceInfoMap_.end()) {
        HILOGE("SoftbusAdapter::SoftbusJoinLnn deviceInfo not found: %{public}s", GetAnonyString(devId).c_str());
        return ERR_INVALID_OPERATION;
    }

    DeviceInfo *deviceInfo = iter->second.get();
    if (deviceInfo->addrNum <= 0 || deviceInfo->addrNum >= CONNECTION_ADDR_MAX) {
        HILOGE("deviceInfo addrNum not valid, addrNum %{public}d", deviceInfo->addrNum);
        return ERR_DEVICEMANAGER_OPERATION_FAILED;
    }

    for (unsigned int i = 0; i < deviceInfo->addrNum; i++) {
        // currently, only support CONNECT_ADDR_WLAN
        if (deviceInfo->addr[i].type != ConnectionAddrType::CONNECTION_ADDR_WLAN &&
            deviceInfo->addr[i].type != ConnectionAddrType::CONNECTION_ADDR_ETH) {
            continue;
        }

        HILOGI("SoftbusAdapter::SoftbusJoinLnn call softbus JoinLNN.");
        return JoinLNN(DEVICE_MANAGER_PACKAGE_NAME.c_str(), &deviceInfo->addr[i], OnSoftbusJoinLNNResult);
    }

    return ERR_DEVICEMANAGER_OPERATION_FAILED;
}

int32_t SoftbusAdapter::SoftbusLeaveLnn(std::string networkId)
{
    return LeaveLNN(networkId.c_str(), OnSoftbusLeaveLNNResult);
}

int32_t SoftbusAdapter::GetConnectionIpAddr(std::string deviceId, std::string &ipAddr)
{
    auto iter = discoverDeviceInfoMap_.find(deviceId);
    if (iter == discoverDeviceInfoMap_.end()) {
        HILOGE("deviceInfo not found by deviceId %{public}s", GetAnonyString(deviceId).c_str());
        return ERR_INVALID_OPERATION;
    }

    DeviceInfo *deviceInfo = iter->second.get();
    if (deviceInfo->addrNum <= 0 || deviceInfo->addrNum >= CONNECTION_ADDR_MAX) {
        HILOGE("deviceInfo addrNum not valid, addrNum %{public}d", deviceInfo->addrNum);
        return ERR_DEVICEMANAGER_OPERATION_FAILED;
    }

    for (unsigned int i = 0; i < deviceInfo->addrNum; ++i) {
        // currently, only support CONNECT_ADDR_WLAN
        if (deviceInfo->addr[i].type != ConnectionAddrType::CONNECTION_ADDR_WLAN &&
            deviceInfo->addr[i].type != ConnectionAddrType::CONNECTION_ADDR_ETH) {
            continue;
        }
        ipAddr = deviceInfo->addr[i].info.ip.ip;
        HILOGI("SoftbusAdapter::GetConnectionIpAddr get ip ok.");
        return ERR_OK;
    }
    HILOGE("failed to get ipAddr for deviceId %{public}s", GetAnonyString(deviceId).c_str());
    return ERR_DEVICEMANAGER_OPERATION_FAILED;
}

const std::map<std::string, std::vector<std::shared_ptr<SubscribeInfoAdapter>>>& SoftbusAdapter::GetsubscribeInfos()
{
    return subscribeInfos_;
}

void SoftbusAdapter::SaveDiscoverDeviceInfo(const DeviceInfo *deviceInfo)
{
    std::shared_ptr<DeviceInfo> info = std::make_shared<DeviceInfo>();
    DeviceInfo *infoPtr = info.get();
    if (memcpy_s(infoPtr, sizeof(DeviceInfo), deviceInfo, sizeof(DeviceInfo)) != 0) {
        HILOGE("SoftbusAdapter::SaveDiscoverDeviceInfo failed.");
        return;
    }

    std::string deviceId = deviceInfo->devId;
    discoverDeviceInfoMap_[deviceId] = info;
    discoverDeviceInfoVector_.push_back(info);

    // Remove the earliest element when reached the max size
    if (discoverDeviceInfoVector_.size() == DISCOVER_DEVICEINFO_MAX_SIZE) {
        auto iter = discoverDeviceInfoVector_.begin();
        std::string delDevId = iter->get()->devId;
        discoverDeviceInfoMap_.erase(delDevId);
        discoverDeviceInfoVector_.erase(iter);
    }
}

void SoftbusAdapter::RemoveDiscoverDeviceInfo(const std::string deviceId)
{
    discoverDeviceInfoMap_.erase(deviceId);
    auto iter = discoverDeviceInfoVector_.begin();
    while (iter != discoverDeviceInfoVector_.end()) {
        if (strcmp(iter->get()->devId, deviceId.c_str()) == 0) {
            iter = discoverDeviceInfoVector_.erase(iter);
        } else {
            ++iter;
        }
    }
}
} // namespace DistributedHardware
} // namespace OHOS
