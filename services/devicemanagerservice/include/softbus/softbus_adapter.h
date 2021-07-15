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

#ifndef OHOS_DEVICE_MANAGER_SOFTBUS_ADAPTER_H
#define OHOS_DEVICE_MANAGER_SOFTBUS_ADAPTER_H

#include <string>
#include <map>
#include <memory>
#include "softbus_bus_center.h"
#include "discovery_service.h"
#include "dm_device_info.h"
#include "dm_subscribe_info.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedHardware {
struct SubscribeInfoAdapter {
    SubscribeInfo info;
    uint16_t subscribeIdOrigin;
    uint16_t subscribeIdPrefix;
};

class SoftbusAdapter {
DECLARE_SINGLE_INSTANCE(SoftbusAdapter);
public:
    static int32_t GetSoftbusTrustDevices(const std::string &packageName, std::string &extra,
        std::vector<DmDeviceInfo> &deviceList);
    void RegSoftBusDeviceStateListener();
    int32_t StartSoftbusDiscovery(std::string &packageName, DmSubscribeInfo &info);
    int32_t StopSoftbusDiscovery(std::string &packageName, uint16_t subscribeId);
    static void OnSoftbusDeviceOffline(NodeBasicInfo *info);
    static void OnSoftBusDeviceOnline(NodeBasicInfo *info);
    static void OnSoftbusDeviceInfoChanged(NodeBasicInfoType type, NodeBasicInfo *info);
    static void OnSoftbusDeviceFound(const DeviceInfo *device);
    static void OnSoftbusDiscoverFailed(int subscribeId, DiscoveryFailReason failReason);
    static void OnSoftbusDiscoverySuccess(int subscribeId);
    static void OnSoftbusJoinLNNResult(ConnectionAddr *addr, const char *networkId, int32_t retCode);
    static void OnSoftbusLeaveLNNResult(const char *networkId, int32_t retCode);
    const std::map<std::string, std::vector<std::shared_ptr<SubscribeInfoAdapter>>>& GetsubscribeInfos();
    int32_t SoftbusJoinLnn(std::string devId);
    int32_t SoftbusLeaveLnn(std::string networkId);
    int32_t GetConnectionIpAddr(std::string deviceId, std::string &ipAddr);

private:
    static void OnSoftBusDeviceStateChange(DmDeviceState state, NodeBasicInfo *info);
    static bool IsDeviceOnLine(std::string &deviceId);
    std::string GetPackageNameBySubscribeId(uint16_t subscribeId);
    bool GetsubscribeIdAdapter(std::string packageName, int16_t originId, int32_t &adapterId);
    bool GetPackageNameBySubscribeId(int32_t adapterId, std::string &packageName);
    void SaveDiscoverDeviceInfo(const DeviceInfo *deviceInfo);
    void RemoveDiscoverDeviceInfo(const std::string deviceId);

private:
    std::map<std::string, std::vector<std::shared_ptr<SubscribeInfoAdapter>>> subscribeInfos_;
    std::map<std::string, std::shared_ptr<DeviceInfo>> discoverDeviceInfoMap_;
    std::vector<std::shared_ptr<DeviceInfo>> discoverDeviceInfoVector_;
    std::atomic<uint16_t> subscribeIdPrefix {0};
    INodeStateCb softbusNodeStateCb = {
        .events = EVENT_NODE_STATE_ONLINE | EVENT_NODE_STATE_OFFLINE | EVENT_NODE_STATE_INFO_CHANGED,
        .onNodeOnline = OnSoftBusDeviceOnline,
        .onNodeOffline = OnSoftbusDeviceOffline,
        .onNodeBasicInfoChanged = OnSoftbusDeviceInfoChanged
    };
    IDiscoveryCallback softbusDiscoverCallback = {
        .OnDeviceFound = OnSoftbusDeviceFound,
        .OnDiscoverFailed = OnSoftbusDiscoverFailed,
        .OnDiscoverySuccess = OnSoftbusDiscoverySuccess
    };
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DEVICE_MANAGER_SOFTBUS_ADAPTER_H
