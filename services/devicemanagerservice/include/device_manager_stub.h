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

#ifndef OHOS_DEVICE_MANAGER_STUB_H
#define OHOS_DEVICE_MANAGER_STUB_H

#include <map>
#include "iremote_stub.h"
#include "idevice_manager.h"

namespace OHOS {
namespace DistributedHardware {
class DeviceManagerStub : public IRemoteStub<IDeviceManager> {
public:
    DeviceManagerStub();
    ~DeviceManagerStub();
    int32_t OnRemoteRequest(uint32_t code,
        MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
private:
    int32_t RegisterDeviceManagerListenerInner(MessageParcel &data, MessageParcel &reply);
    int32_t UnRegisterDeviceManagerListenerInner(MessageParcel &data, MessageParcel &reply);
    int32_t RegisterDeviceStateCallbackInner(MessageParcel &data, MessageParcel &reply);
    int32_t UnRegisterDeviceStateCallbackInner(MessageParcel &data, MessageParcel &reply);
    int32_t GetTrustedDeviceListInner(MessageParcel &data, MessageParcel &reply);
    int32_t StartDeviceDiscoveryInner(MessageParcel &data, MessageParcel &reply);
    int32_t StopDeviceDiscoveryInner(MessageParcel &data, MessageParcel &reply);
    int32_t AuthenticateDeviceInner(MessageParcel &data, MessageParcel &reply);
    template<typename T>
    int32_t GetParcelableInfo(MessageParcel &reply, T &parcelableInfo);
    bool EnforceInterceToken(MessageParcel &data);
    using CmdProcFunc = int32_t (DeviceManagerStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, CmdProcFunc> memberFuncMap_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DEVICE_MANAGER_STUB_H
