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

#include "device_manager_proxy.h"

#include "ipc_types.h"

#include "device_manager_log.h"

namespace OHOS {
namespace DistributedHardware {
bool DeviceManagerProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(DeviceManagerProxy::GetDescriptor())) {
        HILOGE("write interface token failed");
        return false;
    }
    return true;
}

int32_t DeviceManagerProxy::RegisterDeviceManagerListener(std::string &packageName, sptr<IRemoteObject> listener)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote service null");
        return ERR_NULL_OBJECT;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteString(packageName)) {
        HILOGE("write packageName failed");
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteRemoteObject(listener)) {
        HILOGE("write callback failed");
        return ERR_FLATTEN_OBJECT;
    }

    int32_t error = remote->SendRequest(REGISTER_DEVICE_MANAGER_LISTENER, data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("RegisterDeviceManagerListener SendRequest fail, error: %{public}d", error);
        return error;
    }
    return ERR_NONE;
}

int32_t DeviceManagerProxy::UnRegisterDeviceManagerListener(std::string &packageName)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote service null");
        return ERR_NULL_OBJECT;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteString(packageName)) {
        HILOGE("write packageName failed");
        return ERR_FLATTEN_OBJECT;
    }

    int32_t error = remote->SendRequest(UNREGISTER_DEVICE_MANAGER_LISTENER, data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("UnRegisterDeviceManagerListener SendRequest fail, error: %{public}d", error);
        return error;
    }
    return ERR_NONE;
}

int32_t DeviceManagerProxy::RegisterDeviceStateCallback(std::string &packageName, std::string &extra)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote service null");
        return ERR_NULL_OBJECT;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteString(packageName)) {
        HILOGE("write packageName failed");
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteString(extra)) {
        HILOGE("write extra failed");
        return ERR_FLATTEN_OBJECT;
    }

    int32_t error = remote->SendRequest(REGISTER_DEVICE_STATE_CALLBACK, data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("RegisterDeviceStateCallback SendRequest fail, error: %{public}d", error);
        return error;
    }
    return ERR_NONE;
}

int32_t DeviceManagerProxy::UnRegisterDeviceStateCallback(std::string &packageName)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote service null");
        return ERR_NULL_OBJECT;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteString(packageName)) {
        HILOGE("write packageName failed");
        return ERR_FLATTEN_OBJECT;
    }

    int32_t error = remote->SendRequest(UNREGISTER_DEVICE_STATE_CALLBACK, data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("UnRegisterDeviceStateCallback SendRequest fail, error: %{public}d", error);
        return error;
    }
    return ERR_NONE;
}

template<typename T>
int32_t DeviceManagerProxy::GetParcelableInfos(MessageParcel &reply, std::vector<T> &parcelableInfos)
{
    int32_t infoSize = reply.ReadInt32();
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(reply.ReadParcelable<T>());
        if (!info) {
            HILOGE("Read Parcelable infos failed");
            return ERR_INVALID_VALUE;
        }
        parcelableInfos.emplace_back(*info);
    }
    HILOGI("get parcelable infos success");
    return ERR_NONE;
}

int32_t DeviceManagerProxy::GetTrustedDeviceList(std::string &packageName, std::string &extra,
    std::vector<DmDeviceInfo> &deviceList)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote service null");
        return ERR_NULL_OBJECT;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteString(packageName)) {
        HILOGE("write packageName failed");
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteString(extra)) {
        HILOGE("write extra failed");
        return ERR_FLATTEN_OBJECT;
    }

    int32_t error = remote->SendRequest(GET_TRUST_DEVICE_LIST, data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("GetTrustedDeviceList SendRequest fail, error: %{public}d", error);
        return error;
    }

    error = GetParcelableInfos(reply, deviceList);
    if (error != ERR_NONE) {
        HILOGE("GetTrustedDeviceList GetParcelableInfos fail, error: %{public}d", error);
        return error;
    }
    return ERR_NONE;
}

int32_t DeviceManagerProxy::StartDeviceDiscovery(std::string &packageName, DmSubscribeInfo &subscribeInfo)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote service null");
        return ERR_NULL_OBJECT;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteString(packageName)) {
        HILOGE("write packageName failed");
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteParcelable(&subscribeInfo)) {
        HILOGE("write subscribeInfo failed");
        return ERR_FLATTEN_OBJECT;
    }

    int32_t error = remote->SendRequest(START_DEVICE_DISCOVER, data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("StartDeviceDiscovery SendRequest fail, error: %{public}d", error);
        return error;
    }
    return ERR_NONE;
}

int32_t DeviceManagerProxy::StopDeviceDiscovery(std::string &packageName, uint16_t subscribeId)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote service null");
        return ERR_NULL_OBJECT;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteString(packageName)) {
        HILOGE("write packageName failed");
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteInt16(subscribeId)) {
        HILOGE("write subscribeInfo failed");
        return ERR_FLATTEN_OBJECT;
    }

    int32_t error = remote->SendRequest(STOP_DEVICE_DISCOVER, data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("StopDeviceDiscovery SendRequest fail, error: %{public}d", error);
        return error;
    }
    return ERR_NONE;
}

int32_t DeviceManagerProxy::AuthenticateDevice(std::string &packageName, const DmDeviceInfo &deviceInfo,
    std::string &extra)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote service null");
        return ERR_NULL_OBJECT;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteString(packageName)) {
        HILOGE("write packageName failed");
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteParcelable(&deviceInfo)) {
        HILOGE("write deviceInfo failed");
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteString(extra)) {
        HILOGE("write extra failed");
        return ERR_FLATTEN_OBJECT;
    }

    int32_t error = remote->SendRequest(AUTHENTICATE_DEVICE, data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("AuthenticateDevice SendRequest fail, error: %{public}d", error);
        return error;
    }
    return ERR_NONE;
}
} // namespace DistributedHardware
} // namespace OHOS
