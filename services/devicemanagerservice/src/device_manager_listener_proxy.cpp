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

#include "device_manager_listener_proxy.h"

#include "ipc_types.h"

#include "device_manager_log.h"

namespace OHOS {
namespace DistributedHardware {
bool DeviceManagerListenerProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(DeviceManagerListenerProxy::GetDescriptor())) {
        HILOGE("write interface token failed");
        return false;
    }
    return true;
}

int32_t DeviceManagerListenerProxy::OnDeviceOnline(std::string &packageName, const DmDeviceInfo &deviceInfo)
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

    int32_t error = remote->SendRequest(ON_DEVICE_ONLINE, data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("OnDeviceOnline SendRequest fail, error: %{public}d", error);
        return error;
    }

    return ERR_NONE;
}

int32_t DeviceManagerListenerProxy::OnDeviceOffline(std::string &packageName, const DmDeviceInfo &deviceInfo)
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

    int32_t error = remote->SendRequest(ON_DEVICE_OFFLINE, data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("OnDeviceOffline SendRequest fail, error: %{public}d", error);
        return error;
    }

    return ERR_NONE;
}

int32_t DeviceManagerListenerProxy::OnDeviceChanged(std::string &packageName, const DmDeviceInfo &deviceInfo)
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

    int32_t error = remote->SendRequest(ON_DEVICE_CHANGE, data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("OnDeviceChanged SendRequest fail, error: %{public}d", error);
        return error;
    }

    return ERR_NONE;
}

int32_t DeviceManagerListenerProxy::OnDeviceFound(std::string &packageName, uint16_t subscribeId,
    const DmDeviceInfo &deviceInfo)
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
        HILOGE("write subscribeId failed");
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteParcelable(&deviceInfo)) {
        HILOGE("write deviceInfo failed");
        return ERR_FLATTEN_OBJECT;
    }

    int32_t error = remote->SendRequest(ON_DEVICE_FOUND, data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("OnDeviceFound SendRequest fail, error: %{public}d", error);
        return error;
    }

    return ERR_NONE;
}

int32_t DeviceManagerListenerProxy::OnDiscoverFailed(std::string &packageName, uint16_t subscribeId,
    int32_t failedReason)
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
        HILOGE("write subscribeId failed");
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteInt32(failedReason)) {
        HILOGE("write packageName failed");
        return ERR_FLATTEN_OBJECT;
    }

    int32_t error = remote->SendRequest(ON_DISCOVER_FAILED, data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("OnDiscoverFailed SendRequest fail, error: %{public}d", error);
        return error;
    }

    return ERR_NONE;
}

int32_t DeviceManagerListenerProxy::OnDiscoverySuccess(std::string &packageName, uint16_t subscribeId)
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
        HILOGE("write subscribeId failed");
        return ERR_FLATTEN_OBJECT;
    }

    int32_t error = remote->SendRequest(ON_DISCOVER_SUCCESS, data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("OnDiscoverySuccess SendRequest fail, error: %{public}d", error);
        return error;
    }

    return ERR_NONE;
}

int32_t DeviceManagerListenerProxy::OnAuthResult(std::string &packageName, std::string &deviceId, int32_t status,
    int32_t reason)
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

    if (!data.WriteString(deviceId)) {
        HILOGE("write packageName failed");
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteInt32(status)) {
        HILOGE("write status failed");
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteInt32(reason)) {
        HILOGE("write reason failed");
        return ERR_FLATTEN_OBJECT;
    }

    int32_t error = remote->SendRequest(ON_AUTH_RESULT, data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("OnAuthResult SendRequest fail, error: %{public}d", error);
        return error;
    }

    return ERR_NONE;
}
} // namespace DistributedHardware
} // namespace OHOS
