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

#ifndef OHOS_DEVICE_MANAGER_LISTENER_STUB_H
#define OHOS_DEVICE_MANAGER_LISTENER_STUB_H

#include <map>
#include "iremote_stub.h"
#include "idevice_manager_listener.h"

#include "device_manager_callback.h"

namespace OHOS {
namespace DistributedHardware {
class DeviceManagerListenerStub : public IRemoteStub<IDeviceManagerListener> {
public:
    DeviceManagerListenerStub();
    ~DeviceManagerListenerStub();
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel &reply, MessageOption &option) override;
    int32_t OnDeviceOnline(std::string &packageName, const DmDeviceInfo &deviceInfo) override;
    int32_t OnDeviceOffline(std::string &packageName, const DmDeviceInfo &deviceInfo) override;
    int32_t OnDeviceChanged(std::string &packageName, const DmDeviceInfo &deviceInfo) override;
    int32_t OnDeviceFound(std::string &packageName, uint16_t subscribeId, const DmDeviceInfo &deviceInfo) override;
    int32_t OnDiscoverFailed(std::string &packageName, uint16_t subscribeId, int32_t failedReason) override;
    int32_t OnDiscoverySuccess(std::string &packageName, uint16_t subscribeId) override;
    int32_t OnAuthResult(std::string &packageName, std::string &deviceId, int32_t status, int32_t reason) override;
    void AddDeviceStateCallback(std::shared_ptr<DeviceStateCallback> callback);
    void RemoveDeviceStateCallback();
    void AddDiscoverCallback(uint16_t subscribeId, std::shared_ptr<DiscoverCallback> callback);
    void RemoveDiscoverCallback(uint16_t subscribeId);
    void AddAuthenticateCallback(std::string deviceId, std::shared_ptr<AuthenticateCallback> callback);

private:
    template<typename T>
    int32_t GetParcelableInfo(MessageParcel &reply, T &parcelableInfo);
    int32_t OnDeviceOnlineInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnDeviceOfflineInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnDeviceChangedInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnDeviceFoundInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnDiscoverFailedInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnDiscoverySuccessInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnAuthResultInner(MessageParcel &data, MessageParcel &reply);

    using ListenerFunc = int32_t (DeviceManagerListenerStub::*)(MessageParcel& data, MessageParcel& reply);
    std::map<uint32_t, ListenerFunc> memberFuncMap_;
    std::shared_ptr<DeviceStateCallback> deviceStateCallback_;
    std::map<int16_t, std::shared_ptr<DiscoverCallback>> deviceDiscoverCallbacks_;
    std::map<std::string, std::shared_ptr<AuthenticateCallback>> authenticateCallback_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DEVICE_MANAGER_LISTENER_STUB_H
