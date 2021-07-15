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

#ifndef OHOS_DEVICE_MANAGER_LISTENER_INTERFACE_H
#define OHOS_DEVICE_MANAGER_LISTENER_INTERFACE_H

#include "iremote_broker.h"
#include "dm_device_info.h"

namespace OHOS {
namespace DistributedHardware {
enum {
    ON_DEVICE_ONLINE = 0,
    ON_DEVICE_OFFLINE = 1,
    ON_DEVICE_CHANGE = 2,
    ON_DEVICE_FOUND = 3,
    ON_DISCOVER_SUCCESS = 4,
    ON_DISCOVER_FAILED = 5,
    ON_AUTH_RESULT = 6,
};

class IDeviceManagerListener : public OHOS::IRemoteBroker {
public:
    virtual ~IDeviceManagerListener() {}
    virtual int32_t OnDeviceOnline(std::string &packageName, const DmDeviceInfo &deviceInfo) = 0;
    virtual int32_t OnDeviceOffline(std::string &packageName, const DmDeviceInfo &deviceInfo) = 0;
    virtual int32_t OnDeviceChanged(std::string &packageName, const DmDeviceInfo &deviceInfo) = 0;
    virtual int32_t OnDeviceFound(std::string &packageName, uint16_t subscribeId, const DmDeviceInfo &deviceInfo) = 0;
    virtual int32_t OnDiscoverFailed(std::string &packageName, uint16_t subscribeId, int32_t failedReason) = 0;
    virtual int32_t OnDiscoverySuccess(std::string &packageName, uint16_t subscribeId) = 0;
    virtual int32_t OnAuthResult(std::string &packageName, std::string &deviceId, int32_t status, int32_t reason) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.distributedhardware.devicemanagerlistener");
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DEVICE_MANAGER_LISTENER_INTERFACE_H
