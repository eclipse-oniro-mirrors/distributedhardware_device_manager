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

#include "device_manager_stub.h"

#include "ipc_skeleton.h"
#include "ipc_types.h"


#include "device_manager_log.h"

using namespace std;

namespace OHOS {
namespace DistributedHardware {
DeviceManagerStub::DeviceManagerStub()
{
    memberFuncMap_[GET_TRUST_DEVICE_LIST] = &DeviceManagerStub::GetTrustedDeviceListInner;
    memberFuncMap_[REGISTER_DEVICE_MANAGER_LISTENER] = &DeviceManagerStub::RegisterDeviceManagerListenerInner;
    memberFuncMap_[UNREGISTER_DEVICE_MANAGER_LISTENER] = &DeviceManagerStub::UnRegisterDeviceManagerListenerInner;
    memberFuncMap_[REGISTER_DEVICE_STATE_CALLBACK] = &DeviceManagerStub::RegisterDeviceStateCallbackInner;
    memberFuncMap_[UNREGISTER_DEVICE_STATE_CALLBACK] = &DeviceManagerStub::UnRegisterDeviceStateCallbackInner;
    memberFuncMap_[START_DEVICE_DISCOVER] = &DeviceManagerStub::StartDeviceDiscoveryInner;
    memberFuncMap_[STOP_DEVICE_DISCOVER] = &DeviceManagerStub::StopDeviceDiscoveryInner;
    memberFuncMap_[AUTHENTICATE_DEVICE] = &DeviceManagerStub::AuthenticateDeviceInner;
}

DeviceManagerStub::~DeviceManagerStub()
{
    memberFuncMap_.clear();
}

int32_t DeviceManagerStub::OnRemoteRequest(uint32_t code,
    MessageParcel& data, MessageParcel &reply, MessageOption &option)
{
    HILOGI("code = %{public}d, flags= %{public}d.", code, option.GetFlags());
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            if (!EnforceInterceToken(data)) {
                HILOGE("interface token check failed!");
                return ERR_INVALID_STATE;
            }
            return (this->*memberFunc)(data, reply);
        }
    }
    HILOGW("unsupport code: %{public}d", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t DeviceManagerStub::RegisterDeviceManagerListenerInner(MessageParcel& data, MessageParcel& reply)
{
    string packageName = data.ReadString();
    sptr<IRemoteObject> listener = data.ReadRemoteObject();
    int32_t result = RegisterDeviceManagerListener(packageName, listener);
    if (!reply.WriteInt32(result)) {
        HILOGE("write result failed");
        return ERR_INVALID_VALUE;
    }
    return ERR_NONE;
}

int32_t DeviceManagerStub::UnRegisterDeviceManagerListenerInner(MessageParcel& data, MessageParcel& reply)
{
    string packageName = data.ReadString();
    int32_t result = UnRegisterDeviceManagerListener(packageName);
    if (!reply.WriteInt32(result)) {
        HILOGE("write result failed");
        return ERR_INVALID_VALUE;
    }
    return ERR_NONE;
}

int32_t DeviceManagerStub::RegisterDeviceStateCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    string packageName = data.ReadString();
    string extra = data.ReadString();
    HILOGI("packageName:%{public}s, extra:%{public}s", packageName.c_str(), extra.c_str());
    int32_t result = RegisterDeviceStateCallback(packageName, extra);
    if (!reply.WriteInt32(result)) {
        HILOGE("write result failed");
        return ERR_INVALID_VALUE;
    }
    return ERR_NONE;
}

int32_t DeviceManagerStub::UnRegisterDeviceStateCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    string packageName = data.ReadString();
    HILOGI("packageName:%{public}s", packageName.c_str());
    int32_t result = UnRegisterDeviceStateCallback(packageName);
    if (!reply.WriteInt32(result)) {
        HILOGE("write result failed");
        return ERR_INVALID_VALUE;
    }
    return ERR_NONE;
}

int32_t DeviceManagerStub::GetTrustedDeviceListInner(MessageParcel& data, MessageParcel& reply)
{
    string packageName = data.ReadString();
    string extra = data.ReadString();
    HILOGI("packageName:%{public}s, extra:%{public}s", packageName.c_str(), extra.c_str());
    std::vector<DmDeviceInfo> devInfos;
    int32_t result = GetTrustedDeviceList(packageName, extra, devInfos);
    reply.WriteInt32(devInfos.size());
    for (auto &it : devInfos) {
        if (!reply.WriteParcelable(&it)) {
            return ERR_INVALID_VALUE;
        }
    }
    if (!reply.WriteInt32(result)) {
        HILOGE("write result failed");
        return ERR_INVALID_VALUE;
    }
    return ERR_NONE;
}

template<typename T>
int32_t DeviceManagerStub::GetParcelableInfo(MessageParcel &reply, T &parcelableInfo)
{
    std::unique_ptr<T> info(reply.ReadParcelable<T>());
    if (!info) {
        HILOGE("readParcelableInfo failed");
        return ERR_INVALID_VALUE;
    }
    parcelableInfo = *info;
    return ERR_NONE;
}

int32_t DeviceManagerStub::StartDeviceDiscoveryInner(MessageParcel& data, MessageParcel& reply)
{
    string packageName = data.ReadString();
    DmSubscribeInfo subscribeInfo;
    int32_t result = GetParcelableInfo(data, subscribeInfo);
    if (result != ERR_NONE) {
        HILOGE("GetParcelableInfo fail, result: %{public}d", result);
        reply.WriteInt32(result);
        return result;
    }

    HILOGI("packageName:%{public}s, subscribeId: %{public}d", packageName.c_str(), subscribeInfo.subscribeId);
    result = StartDeviceDiscovery(packageName, subscribeInfo);
    if (!reply.WriteInt32(result)) {
        HILOGE("write result failed");
        return ERR_INVALID_VALUE;
    }
    return ERR_NONE;
}

int32_t DeviceManagerStub::StopDeviceDiscoveryInner(MessageParcel& data, MessageParcel& reply)
{
    string packageName = data.ReadString();
    uint16_t subscribeId = data.ReadInt32();
    HILOGI("packageName:%{public}s, subscribeId: %{public}d", packageName.c_str(), subscribeId);
    int32_t result = StopDeviceDiscovery(packageName, subscribeId);
    if (!reply.WriteInt32(result)) {
        HILOGE("write result failed");
        return ERR_INVALID_VALUE;
    }
    return ERR_NONE;
}

int32_t DeviceManagerStub::AuthenticateDeviceInner(MessageParcel& data, MessageParcel& reply)
{
    string packageName = data.ReadString();
    DmDeviceInfo deviceInfo;
    int32_t result = GetParcelableInfo(data, deviceInfo);
    if (result != ERR_NONE) {
        HILOGE("GetParcelableInfo fail, result: %{public}d", result);
        reply.WriteInt32(result);
        return result;
    }

    string extra = data.ReadString();
    HILOGI("packageName:%{public}s, extra:%{public}s", packageName.c_str(), extra.c_str());
    result = AuthenticateDevice(packageName, deviceInfo, extra);
    if (!reply.WriteInt32(result)) {
        HILOGE("write result failed");
        return ERR_INVALID_VALUE;
    }
    return ERR_NONE;
}

bool DeviceManagerStub::EnforceInterceToken(MessageParcel& data)
{
    u16string interfaceToken = data.ReadInterfaceToken();
    u16string descriptor = DeviceManagerStub::GetDescriptor();
    return interfaceToken == descriptor;
}
} // namespace DistributedHardware
} // namespace OHOS
