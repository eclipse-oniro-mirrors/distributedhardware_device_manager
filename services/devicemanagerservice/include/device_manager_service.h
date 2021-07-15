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

#ifndef OHOS_DEVICE_MANAGER_SERVICE_H
#define OHOS_DEVICE_MANAGER_SERVICE_H

#include <memory>
#include <mutex>
#include <map>
#include <tuple>
#include <vector>
#include "system_ability.h"
#include "thread_pool.h"
#include "iremote_stub.h"
#include "idevice_manager.h"
#include "idevice_manager_listener.h"
#include "device_manager_stub.h"
#include "single_instance.h"
#include "hichain_adapter.h"

namespace OHOS {
namespace DistributedHardware {
enum class ServiceRunningState {
    STATE_NOT_START,
    STATE_RUNNING
};

enum DmBindStatus : uint32_t {
    STATE_BIND_SUCCESS,
    STATE_BIND_FAILD
};

class AppDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    void OnRemoteDied(const wptr<IRemoteObject>& remote) override;
    AppDeathRecipient() = default;
    ~AppDeathRecipient() = default;
};

class HiChainBindCallback : public BindCallback {
public:
    void onBindSuccess(std::string deviceId, const char* returnData) override;
    void onBindFailed(std::string deviceId, int32_t errorCode) override;
};

class DeviceManagerService : public SystemAbility, public DeviceManagerStub {
friend class HiChainBindCallback;
DECLARE_SYSTEM_ABILITY(DeviceManagerService);
DECLARE_SINGLE_INSTANCE_BASE(DeviceManagerService);
public:
    DeviceManagerService();
    ~DeviceManagerService() = default;
    void OnStart() override;
    void OnStop() override;
    ServiceRunningState QueryServiceState() const;

    int32_t GetTrustedDeviceList(std::string &packageName, std::string &extra,
        std::vector<DmDeviceInfo> &deviceList) override;
    int32_t RegisterDeviceManagerListener(std::string &packageName, sptr<IRemoteObject> listener) override;
    int32_t UnRegisterDeviceManagerListener(std::string &packageName) override;
    int32_t RegisterDeviceStateCallback(std::string &packageName, std::string &extra) override;
    int32_t UnRegisterDeviceStateCallback(std::string &packageName) override;
    int32_t StartDeviceDiscovery(std::string &packageName, DmSubscribeInfo &subscribeInfo) override;
    int32_t StopDeviceDiscovery(std::string &packageName, uint16_t subscribeId) override;
    int32_t AuthenticateDevice(std::string &packageName, const DmDeviceInfo &deviceInfo, std::string &extra) override;
    const std::map<std::string, sptr<IRemoteObject>>& GetDmListener();
    const sptr<IDeviceManagerListener> GetDmListener(std::string packageName) const;

private:
    bool Init();
    void RegisterDeviceStateListener();

private:
    bool registerToService_;
    ServiceRunningState state_;
    mutable ThreadPool threadPool_;
    std::mutex listenerLock_;
    std::shared_ptr<HiChainBindCallback> hichainBindCallback_;
    std::map<std::string, sptr<AppDeathRecipient>> appRecipient_;
    std::map<std::string, sptr<IRemoteObject>> dmListener_;
    std::map<std::string, std::string> devStateCallbackParas_;
    std::map<std::string, std::string> authCallbackParas_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DEVICE_MANAGER_SERVICE_H
