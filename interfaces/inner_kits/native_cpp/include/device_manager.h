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

#ifndef OHOS_DEVICE_MANAGER_H
#define OHOS_DEVICE_MANAGER_H
#include "iremote_object.h"

#include <set>

#include "device_manager_callback.h"
#include "device_manager_listener_stub.h"
#include "idevice_manager.h"
#include "single_instance.h"
#include "dm_subscribe_info.h"

namespace OHOS {
namespace DistributedHardware {
class DmDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    void OnRemoteDied(const wptr<IRemoteObject>& remote) override;
    DmDeathRecipient() = default;
    ~DmDeathRecipient() = default;
};

class DeviceManager {
friend class DmDeathRecipient;
DECLARE_SINGLE_INSTANCE(DeviceManager);
public:
    int32_t InitDeviceManager(std::string &packageName, std::shared_ptr<DmInitCallback> dmInitCallback);
    int32_t UnInitDeviceManager(std::string &packageName);
    int32_t GetTrustedDeviceList(std::string &packageName, std::string &extra,
        std::vector<DmDeviceInfo> &deviceList);
    int32_t RegisterDevStateCallback(std::string &packageName, std::string &extra,
        std::shared_ptr<DeviceStateCallback> callback);
    int32_t UnRegisterDevStateCallback(std::string &packageName);
    int32_t StartDeviceDiscovery(std::string &packageName, DmSubscribeInfo &subscribeInfo,
        std::shared_ptr<DiscoverCallback> callback);
    int32_t StopDeviceDiscovery(std::string &packageName, uint16_t subscribeId);
    int32_t AuthenticateDevice(std::string &packageName, const DmDeviceInfo &deviceInfo, std::string &extra,
        std::shared_ptr<AuthenticateCallback> callback);

private:
    int32_t InitDeviceManagerService();
    bool IsInit(std::string &packageName);

private:
    std::mutex lock_;
    sptr<IDeviceManager> dmInterface_;
    sptr<DmDeathRecipient> dmRecipient_;
    std::map<std::string, sptr<DeviceManagerListenerStub>> dmListener_;
    std::map<std::string, std::shared_ptr<DmInitCallback>> dmInitCallback_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DEVICE_MANAGER_H
