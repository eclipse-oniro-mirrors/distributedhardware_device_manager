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

#ifndef OHOS_DEVICE_MANAGER_PROXY_H
#define OHOS_DEVICE_MANAGER_PROXY_H

#include "idevice_manager.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace DistributedHardware {
class DeviceManagerProxy : public IRemoteProxy<IDeviceManager> {
public:
    explicit DeviceManagerProxy(const sptr<IRemoteObject>& impl) : IRemoteProxy<IDeviceManager>(impl) {};
    ~DeviceManagerProxy() {};

    int32_t GetTrustedDeviceList(std::string &packageName, std::string &extra,
        std::vector<DmDeviceInfo> &deviceList) override;
    int32_t RegisterDeviceManagerListener(std::string &packageName, sptr<IRemoteObject> listener) override;
    int32_t UnRegisterDeviceManagerListener(std::string &packageName) override;
    int32_t RegisterDeviceStateCallback(std::string &packageName, std::string &extra) override;
    int32_t UnRegisterDeviceStateCallback(std::string &packageName) override;
    int32_t StartDeviceDiscovery(std::string &packageName, DmSubscribeInfo &subscribeInfo) override;
    int32_t StopDeviceDiscovery(std::string &packageName, uint16_t subscribeId) override;
    int32_t AuthenticateDevice(std::string &packageName, const DmDeviceInfo &deviceInfo, std::string &extra) override;

private:
    template<typename T>
    int32_t GetParcelableInfos(MessageParcel &reply, std::vector<T> &parcelableInfos);
    bool WriteInterfaceToken(MessageParcel &data);

private:
    static inline BrokerDelegator<DeviceManagerProxy> delegator_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DEVICE_MANAGER_PROXY_H
