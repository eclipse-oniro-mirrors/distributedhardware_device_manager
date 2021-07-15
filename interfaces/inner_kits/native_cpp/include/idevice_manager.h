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

#ifndef OHOS_DEVICE_MANAGER_INTERFACE_H
#define OHOS_DEVICE_MANAGER_INTERFACE_H

#include "iremote_broker.h"
#include "dm_device_info.h"
#include "dm_subscribe_info.h"

namespace OHOS {
namespace DistributedHardware {
enum {
    REGISTER_DEVICE_MANAGER_LISTENER = 0,
    UNREGISTER_DEVICE_MANAGER_LISTENER = 1,
    REGISTER_DEVICE_STATE_CALLBACK = 2,
    UNREGISTER_DEVICE_STATE_CALLBACK = 3,
    GET_TRUST_DEVICE_LIST = 4,
    START_DEVICE_DISCOVER = 5,
    STOP_DEVICE_DISCOVER = 6,
    AUTHENTICATE_DEVICE = 7,
};

class IDeviceManager : public OHOS::IRemoteBroker {
public:
    virtual ~IDeviceManager() {}
    virtual int32_t GetTrustedDeviceList(std::string &packageName, std::string &extra,
        std::vector<DmDeviceInfo> &deviceList) = 0;
    virtual int32_t RegisterDeviceManagerListener(std::string &packageName, sptr<IRemoteObject> listener) = 0;
    virtual int32_t UnRegisterDeviceManagerListener(std::string &packageName) = 0;
    virtual int32_t RegisterDeviceStateCallback(std::string &packageName, std::string &extra) = 0;
    virtual int32_t UnRegisterDeviceStateCallback(std::string &packageName) = 0;
    virtual int32_t StartDeviceDiscovery(std::string &packageName, DmSubscribeInfo &subscribeInfo) = 0;
    virtual int32_t StopDeviceDiscovery(std::string &packageName, uint16_t subscribeId) = 0;
    virtual int32_t AuthenticateDevice(std::string &packageName, const DmDeviceInfo &deviceInfo,
        std::string &extra) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.distributedhardware.devicemanager");
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DEVICE_MANAGER_INTERFACE_H
