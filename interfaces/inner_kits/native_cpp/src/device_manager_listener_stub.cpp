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

#include "device_manager_listener_stub.h"

#include "ipc_skeleton.h"
#include "ipc_types.h"

#include "device_manager_log.h"

using namespace std;

namespace OHOS {
namespace DistributedHardware {
DeviceManagerListenerStub::DeviceManagerListenerStub()
{
    memberFuncMap_[ON_DEVICE_ONLINE] = &DeviceManagerListenerStub::OnDeviceOnlineInner;
    memberFuncMap_[ON_DEVICE_OFFLINE] = &DeviceManagerListenerStub::OnDeviceOfflineInner;
    memberFuncMap_[ON_DEVICE_CHANGE] = &DeviceManagerListenerStub::OnDeviceChangedInner;
    memberFuncMap_[ON_DEVICE_FOUND] = &DeviceManagerListenerStub::OnDeviceFoundInner;
    memberFuncMap_[ON_DISCOVER_SUCCESS] = &DeviceManagerListenerStub::OnDiscoverySuccessInner;
    memberFuncMap_[ON_DISCOVER_FAILED] = &DeviceManagerListenerStub::OnDiscoverFailedInner;
    memberFuncMap_[ON_AUTH_RESULT] = &DeviceManagerListenerStub::OnAuthResultInner;
}

DeviceManagerListenerStub::~DeviceManagerListenerStub()
{
    memberFuncMap_.clear();
}

int32_t DeviceManagerListenerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    HILOGI("code = %{public}d, flags= %{public}d.", code, option.GetFlags());
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (data.ReadInterfaceToken() != DeviceManagerListenerStub::GetDescriptor()) {
            HILOGE("interface token check failed!");
            return ERR_INVALID_STATE;
        }
        return (this->*memberFunc)(data, reply);
    }
    HILOGW("unsupport code: %{public}d", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

template<typename T>
int32_t DeviceManagerListenerStub::GetParcelableInfo(MessageParcel &reply, T &parcelableInfo)
{
    std::unique_ptr<T> info(reply.ReadParcelable<T>());
    if (!info) {
        HILOGE("readParcelableInfo failed");
        return ERR_INVALID_VALUE;
    }
    parcelableInfo = *info;
    return ERR_NONE;
}

int32_t DeviceManagerListenerStub::OnDeviceOnlineInner(MessageParcel &data, MessageParcel &reply)
{
    string packageName = data.ReadString();
    DmDeviceInfo deviceInfo;
    int32_t result = GetParcelableInfo(data, deviceInfo);
    if (result != ERR_NONE) {
        HILOGE("GetParcelableInfo fail, result: %{public}d", result);
        reply.WriteInt32(result);
        return result;
    }

    int32_t ret = OnDeviceOnline(packageName, deviceInfo);
    reply.WriteInt32(ret);
    return ret;
}

int32_t DeviceManagerListenerStub::OnDeviceOfflineInner(MessageParcel &data, MessageParcel &reply)
{
    string packageName = data.ReadString();
    DmDeviceInfo deviceInfo;
    int32_t result = GetParcelableInfo(data, deviceInfo);
    if (result != ERR_NONE) {
        HILOGE("GetParcelableInfo fail, result: %{public}d", result);
        reply.WriteInt32(result);
        return result;
    }

    int32_t ret = OnDeviceOffline(packageName, deviceInfo);
    reply.WriteInt32(ret);
    return ret;
}

int32_t DeviceManagerListenerStub::OnDeviceChangedInner(MessageParcel &data, MessageParcel &reply)
{
    string packageName = data.ReadString();
    DmDeviceInfo deviceInfo;
    int32_t result = GetParcelableInfo(data, deviceInfo);
    if (result != ERR_NONE) {
        HILOGE("GetParcelableInfo deviceInfo fail, result: %{public}d", result);
        reply.WriteInt32(result);
        return result;
    }

    int32_t ret = OnDeviceChanged(packageName, deviceInfo);
    reply.WriteInt32(ret);
    return ret;
}

int32_t DeviceManagerListenerStub::OnDeviceFoundInner(MessageParcel &data, MessageParcel &reply)
{
    string packageName = data.ReadString();
    uint16_t subscribeId = data.ReadInt16();
    DmDeviceInfo deviceInfo;
    int32_t result = GetParcelableInfo(data, deviceInfo);
    if (result != ERR_NONE) {
        HILOGE("GetParcelableInfo fail, result: %{public}d", result);
        reply.WriteInt32(result);
        return result;
    }

    int32_t ret = OnDeviceFound(packageName, subscribeId, deviceInfo);
    reply.WriteInt32(ret);
    return ret;
}

int32_t DeviceManagerListenerStub::OnDiscoverFailedInner(MessageParcel &data, MessageParcel &reply)
{
    string packageName = data.ReadString();
    uint16_t subscribeId = data.ReadInt16();
    int32_t failedReason = data.ReadInt32();

    int32_t ret = OnDiscoverFailed(packageName, subscribeId, failedReason);
    reply.WriteInt32(ret);
    return ret;
}

int32_t DeviceManagerListenerStub::OnDiscoverySuccessInner(MessageParcel &data, MessageParcel &reply)
{
    string packageName = data.ReadString();
    uint16_t subscribeId = data.ReadInt16();

    int32_t ret = OnDiscoverySuccess(packageName, subscribeId);
    reply.WriteInt32(ret);
    return ret;
}

int32_t DeviceManagerListenerStub::OnAuthResultInner(MessageParcel &data, MessageParcel &reply)
{
    string packageName = data.ReadString();
    string deviceId = data.ReadString();
    int32_t status = data.ReadInt32();
    int32_t reason = data.ReadInt32();

    int32_t ret = OnAuthResult(packageName, deviceId, status, reason);
    reply.WriteInt32(ret);
    return ret;
}

int32_t DeviceManagerListenerStub::OnDeviceOnline(std::string &packageName, const DmDeviceInfo &deviceInfo)
{
    HILOGI("OnDeviceOnline packageName:%{public}s", packageName.c_str());
    if (deviceStateCallback_ == nullptr) {
        HILOGE("OnDeviceOnlinecallback not register");
        return ERR_NULL_OBJECT;
    }
    deviceStateCallback_->OnDeviceOnline(deviceInfo);
    return ERR_OK;
}

int32_t DeviceManagerListenerStub::OnDeviceOffline(std::string &packageName, const DmDeviceInfo &deviceInfo)
{
    HILOGI("OnDeviceOffline packageName:%{public}s", packageName.c_str());
    if (deviceStateCallback_ == nullptr) {
        HILOGE("OnDeviceOnlinecallback not register");
        return ERR_NULL_OBJECT;
    }
    deviceStateCallback_->OnDeviceOffline(deviceInfo);
    return ERR_OK;
}

int32_t DeviceManagerListenerStub::OnDeviceChanged(std::string &packageName, const DmDeviceInfo &deviceInfo)
{
    HILOGI("OnDeviceChanged packageName:%{public}s", packageName.c_str());
    if (deviceStateCallback_ == nullptr) {
        HILOGE("OnDeviceOnlinecallback not register");
        return ERR_NULL_OBJECT;
    }
    deviceStateCallback_->OnDeviceChanged(deviceInfo);
    return ERR_OK;
}

int32_t DeviceManagerListenerStub::OnDeviceFound(std::string &packageName, uint16_t subscribeId,
    const DmDeviceInfo &deviceInfo)
{
    HILOGI("OnDeviceFound packageName:%{public}s, subscribeId:%{public}d.", packageName.c_str(), (int32_t)subscribeId);
    auto iter = deviceDiscoverCallbacks_.find(subscribeId);
    if (iter == deviceDiscoverCallbacks_.end()) {
        HILOGE("OnDeviceFound: no register discoverCallback for subscribeId %{public}d", subscribeId);
        return ERR_NULL_OBJECT;
    }
    auto callback = iter->second;
    if (callback == nullptr) {
        HILOGE("OnDeviceFound: discoverCallback is nullptr for subscribeId %{public}d", subscribeId);
        return ERR_NULL_OBJECT;
    }
    callback->OnDeviceFound(subscribeId, const_cast<DmDeviceInfo &>(deviceInfo));
    return ERR_OK;
}

int32_t DeviceManagerListenerStub::OnDiscoverFailed(std::string &packageName, uint16_t subscribeId,
    int32_t failedReason)
{
    HILOGI("OnDiscoverFailed packageName:%{public}s, subscribeId %{public}d, reason %{public}d",
        packageName.c_str(), subscribeId, failedReason);
    auto iter = deviceDiscoverCallbacks_.find(subscribeId);
    if (iter == deviceDiscoverCallbacks_.end()) {
        HILOGE("OnDiscoverFailed: no register discoverCallback for subscribeId %{public}d", subscribeId);
        return ERR_NULL_OBJECT;
    }
    auto callback = iter->second;
    if (callback == nullptr) {
        HILOGE("OnDiscoverFailed: discoverCallback is nullptr for subscribeId %{public}d", subscribeId);
        return ERR_NULL_OBJECT;
    }
    callback->OnDiscoverFailed(subscribeId, failedReason);
    return ERR_OK;
}

int32_t DeviceManagerListenerStub::OnDiscoverySuccess(std::string &packageName, uint16_t subscribeId)
{
    HILOGI("OnDiscoverySuccess packageName:%{public}s, subscribeId %{public}d", packageName.c_str(), subscribeId);
    auto iter = deviceDiscoverCallbacks_.find(subscribeId);
    if (iter == deviceDiscoverCallbacks_.end()) {
        HILOGE("OnDiscoverySuccess: no register discoverCallback for subscribeId %{public}d", subscribeId);
        return ERR_NULL_OBJECT;
    }
    auto callback = iter->second;
    if (callback == nullptr) {
        HILOGE("OnDiscoverySuccess: discoverCallback is nullptr for subscribeId %{public}d", subscribeId);
        return ERR_NULL_OBJECT;
    }
    callback->OnDiscoverySuccess(subscribeId);
    return ERR_OK;
}

int32_t DeviceManagerListenerStub::OnAuthResult(std::string &packageName, std::string &deviceId, int32_t status,
    int32_t reason)
{
    HILOGI("OnAuthResult packageName:%{public}s, status %{public}d, reason %{public}d",
        packageName.c_str(), status, reason);
    auto iter = authenticateCallback_.find(deviceId);
    if (iter == authenticateCallback_.end()) {
        HILOGE("OnAuthResult: cannot find Auth callback");
        return ERR_NULL_OBJECT;
    }
    auto callback = iter->second;
    if (callback == nullptr) {
        HILOGE("OnAuthResult: Auth callback is nullptr");
        return ERR_NULL_OBJECT;
    }
    callback->OnAuthResult(deviceId, status, reason);
    authenticateCallback_.erase(deviceId);
    return ERR_OK;
}

void DeviceManagerListenerStub::AddDeviceStateCallback(std::shared_ptr<DeviceStateCallback> callback)
{
    deviceStateCallback_ = callback;
}

void DeviceManagerListenerStub::RemoveDeviceStateCallback()
{
    deviceStateCallback_ = nullptr;
}

void DeviceManagerListenerStub::AddDiscoverCallback(uint16_t subscribeId, std::shared_ptr<DiscoverCallback> callback)
{
    deviceDiscoverCallbacks_[subscribeId] = callback;
}

void DeviceManagerListenerStub::RemoveDiscoverCallback(uint16_t subscribeId)
{
    deviceDiscoverCallbacks_.erase(subscribeId);
}

void DeviceManagerListenerStub::AddAuthenticateCallback(std::string deviceId,
    std::shared_ptr<AuthenticateCallback> callback)
{
    authenticateCallback_[deviceId] = callback;
}
} // namespace DistributedHardware
} // namespace OHOS
