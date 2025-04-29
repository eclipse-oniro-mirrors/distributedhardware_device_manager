/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_DM_NOTIFY_H
#define OHOS_DM_NOTIFY_H

#include <chrono>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <set>

#include "device_manager_callback.h"
#include "dm_single_instance.h"
#if !(defined(__LITEOS_M__) || defined(LITE_DEVICE))
#include "ffrt.h"
#endif

namespace OHOS {
namespace DistributedHardware {
class DeviceManagerNotify {
    DM_DECLARE_SINGLE_INSTANCE(DeviceManagerNotify);

public:
    void RegisterDeathRecipientCallback(const std::string &pkgName, std::shared_ptr<DmInitCallback> dmInitCallback);
    void UnRegisterDeathRecipientCallback(const std::string &pkgName);
    void RegisterDeviceStateCallback(const std::string &pkgName, std::shared_ptr<DeviceStateCallback> callback);
    void UnRegisterDeviceStateCallback(const std::string &pkgName);
    void UnRegisterDeviceStatusCallback(const std::string &pkgName);
    void RegisterDeviceStatusCallback(const std::string &pkgName, std::shared_ptr<DeviceStatusCallback> callback);
    void RegisterDiscoveryCallback(const std::string &pkgName, uint16_t subscribeId,
                                   std::shared_ptr<DiscoveryCallback> callback);
    void UnRegisterDiscoveryCallback(const std::string &pkgName, uint16_t subscribeId);
    void RegisterPublishCallback(const std::string &pkgName, int32_t publishId,
        std::shared_ptr<PublishCallback> callback);
    void UnRegisterPublishCallback(const std::string &pkgName, int32_t publishId);
    void RegisterAuthenticateCallback(const std::string &pkgName, const std::string &deviceId,
                                      std::shared_ptr<AuthenticateCallback> callback);
    void UnRegisterAuthenticateCallback(const std::string &pkgName, const std::string &deviceId);
    void UnRegisterPackageCallback(const std::string &pkgName);
    void RegisterDeviceManagerFaCallback(const std::string &pkgName, std::shared_ptr<DeviceManagerUiCallback> callback);
    void UnRegisterDeviceManagerFaCallback(const std::string &pkgName);
    void RegisterCredentialCallback(const std::string &pkgName, std::shared_ptr<CredentialCallback> callback);
    void UnRegisterCredentialCallback(const std::string &pkgName);
    void RegisterBindCallback(const std::string &pkgName, const PeerTargetId &targetId,
        std::shared_ptr<BindTargetCallback> callback);
    void RegisterUnbindCallback(const std::string &pkgName, const PeerTargetId &targetId,
        std::shared_ptr<UnbindTargetCallback> callback);
    void OnBindResult(const std::string &pkgName, const PeerTargetId &targetId, int32_t result, int32_t status,
        std::string content);
    void OnUnbindResult(const std::string &pkgName, const PeerTargetId &targetId, int32_t result, std::string content);
    void RegisterPinHolderCallback(const std::string &pkgName, std::shared_ptr<PinHolderCallback> callback);
    void RegDevTrustChangeCallback(const std::string &pkgName, std::shared_ptr<DevTrustChangeCallback> callback);
    void RegisterDeviceScreenStatusCallback(const std::string &pkgName,
        std::shared_ptr<DeviceScreenStatusCallback> callback);
    void UnRegisterDeviceScreenStatusCallback(const std::string &pkgName);
    void RegisterCredentialAuthStatusCallback(const std::string &pkgName,
        std::shared_ptr<CredentialAuthStatusCallback> callback);
    void UnRegisterCredentialAuthStatusCallback(const std::string &pkgName);
    void RegisterSinkBindCallback(const std::string &pkgName, std::shared_ptr<BindTargetCallback> callback);
    void UnRegisterSinkBindCallback(const std::string &pkgName);

    int32_t RegisterGetDeviceProfileInfoListCallback(const std::string &pkgName,
        std::shared_ptr<GetDeviceProfileInfoListCallback> callback);
    int32_t UnRegisterGetDeviceProfileInfoListCallback(const std::string &pkgName);
    void OnGetDeviceProfileInfoListResult(const std::string &pkgName,
        const std::vector<DmDeviceProfileInfo> &deviceProfileInfos, int32_t code);
    int32_t RegisterGetDeviceIconInfoCallback(const std::string &pkgName, const std::string &uk,
        std::shared_ptr<GetDeviceIconInfoCallback> callback);
    int32_t UnRegisterGetDeviceIconInfoCallback(const std::string &pkgName, const std::string &uk);
    void OnGetDeviceIconInfoResult(const std::string &pkgName, const DmDeviceIconInfo &deviceIconInfo, int32_t code);
    int32_t RegisterSetLocalDeviceNameCallback(const std::string &pkgName,
        std::shared_ptr<SetLocalDeviceNameCallback> callback);
    int32_t UnRegisterSetLocalDeviceNameCallback(const std::string &pkgName);
    void OnSetLocalDeviceNameResult(const std::string &pkgName, int32_t code);
    int32_t RegisterSetRemoteDeviceNameCallback(const std::string &pkgName, const std::string &deviceId,
        std::shared_ptr<SetRemoteDeviceNameCallback> callback);
    int32_t UnRegisterSetRemoteDeviceNameCallback(const std::string &pkgName, const std::string &deviceId);
    void OnSetRemoteDeviceNameResult(const std::string &pkgName, const std::string &deviceId, int32_t code);
    void UnRegisterPinHolderCallback(const std::string &pkgName);

public:
    static void DeviceInfoOnline(const DmDeviceInfo &deviceInfo, std::shared_ptr<DeviceStateCallback> tempCbk);
    static void DeviceInfoOffline(const DmDeviceInfo &deviceInfo, std::shared_ptr<DeviceStateCallback> tempCbk);
    static void DeviceInfoChanged(const DmDeviceInfo &deviceInfo, std::shared_ptr<DeviceStateCallback> tempCbk);
    static void DeviceInfoReady(const DmDeviceInfo &deviceInfo, std::shared_ptr<DeviceStateCallback> tempCbk);
    static void DeviceBasicInfoOnline(const DmDeviceBasicInfo &deviceBasicInfo,
        std::shared_ptr<DeviceStatusCallback> tempCbk);
    static void DeviceBasicInfoOffline(const DmDeviceBasicInfo &deviceBasicInfo,
        std::shared_ptr<DeviceStatusCallback> tempCbk);
    static void DeviceBasicInfoChanged(const DmDeviceBasicInfo &deviceBasicInfo,
        std::shared_ptr<DeviceStatusCallback> tempCbk);
    static void DeviceBasicInfoReady(const DmDeviceBasicInfo &deviceBasicInfo,
        std::shared_ptr<DeviceStatusCallback> tempCbk);
    static void DeviceTrustChange(const std::string &udid, const std::string &uuid, DmAuthForm authForm,
        std::shared_ptr<DevTrustChangeCallback> tempCbk);
public:
    void OnRemoteDied();
    void OnDeviceOnline(const std::string &pkgName, const DmDeviceInfo &deviceInfo);
    void OnDeviceOnline(const std::string &pkgName, const DmDeviceBasicInfo &deviceBasicInfo);
    void OnDeviceOffline(const std::string &pkgName, const DmDeviceInfo &deviceInfo);
    void OnDeviceOffline(const std::string &pkgName, const DmDeviceBasicInfo &deviceBasicInfo);
    void OnDeviceChanged(const std::string &pkgName, const DmDeviceInfo &deviceInfo);
    void OnDeviceChanged(const std::string &pkgName, const DmDeviceBasicInfo &deviceBasicInfo);
    void OnDeviceReady(const std::string &pkgName, const DmDeviceInfo &deviceInfo);
    void OnDeviceReady(const std::string &pkgName, const DmDeviceBasicInfo &deviceBasicInfo);
    void OnDeviceFound(const std::string &pkgName, uint16_t subscribeId, const DmDeviceInfo &deviceInfo);
    void OnDeviceFound(const std::string &pkgName, uint16_t subscribeId, const DmDeviceBasicInfo &deviceBasicInfo);
    void OnDiscoveryFailed(const std::string &pkgName, uint16_t subscribeId, int32_t failedReason);
    void OnDiscoverySuccess(const std::string &pkgName, uint16_t subscribeId);
    void OnPublishResult(const std::string &pkgName, int32_t publishId, int32_t publishResult);
    void OnAuthResult(const std::string &pkgName, const std::string &deviceId, const std::string &token,
                      int32_t status, int32_t reason);
    void OnUiCall(std::string &pkgName, std::string &paramJson);
    void OnCredentialResult(const std::string &pkgName, int32_t &action, const std::string &credentialResult);
    void OnPinHolderCreate(const std::string &deviceId, const std::string &pkgName, DmPinType pinType,
        const std::string &payload);
    void OnPinHolderDestroy(const std::string &pkgName, DmPinType pinType, const std::string &payload);
    void OnCreateResult(const std::string &pkgName, int32_t result);
    void OnDestroyResult(const std::string &pkgName, int32_t result);
    void OnPinHolderEvent(const std::string &pkgName, DmPinHolderEvent event, int32_t result,
                          const std::string &content);
    std::map<std::string, std::shared_ptr<DmInitCallback>> GetDmInitCallback();
    void OnDeviceTrustChange(const std::string &pkgName, const std::string &udid, const std::string &uuid,
        int32_t authForm);
    void OnDeviceScreenStatus(const std::string &pkgName, const DmDeviceInfo &deviceInfo);
    void OnCredentialAuthStatus(const std::string &pkgName, const std::string &deviceList,
                                uint16_t deviceTypeId, int32_t errcode);
    void OnSinkBindResult(const std::string &pkgName, const PeerTargetId &targetId, int32_t result, int32_t status,
        std::string content);
    std::shared_ptr<DiscoveryCallback> GetDiscoveryCallback(const std::string &pkgName, uint16_t subscribeId);
    void GetCallBack(std::map<DmCommonNotifyEvent, std::set<std::string>> &callbackMap);

private:
#if !defined(__LITEOS_M__)
    std::mutex lock_;
#endif
    std::map<std::string, std::shared_ptr<DeviceStateCallback>> deviceStateCallback_;
    std::map<std::string, std::shared_ptr<DeviceStatusCallback>> deviceStatusCallback_;
    std::map<std::string, std::map<uint16_t, std::shared_ptr<DiscoveryCallback>>> deviceDiscoveryCallbacks_;
    std::map<std::string, std::map<int32_t, std::shared_ptr<PublishCallback>>> devicePublishCallbacks_;
    std::map<std::string, std::map<std::string, std::shared_ptr<AuthenticateCallback>>> authenticateCallback_;
    std::map<std::string, std::shared_ptr<DmInitCallback>> dmInitCallback_;
    std::map<std::string, std::shared_ptr<DeviceManagerUiCallback>> dmUiCallback_;
    std::map<std::string, std::shared_ptr<CredentialCallback>> credentialCallback_;
    std::map<std::string, std::map<PeerTargetId, std::shared_ptr<BindTargetCallback>>> bindCallback_;
    std::map<std::string, std::map<PeerTargetId, std::shared_ptr<UnbindTargetCallback>>> unbindCallback_;
    std::map<std::string, std::shared_ptr<PinHolderCallback>> pinHolderCallback_;
    std::map<std::string, std::shared_ptr<DevTrustChangeCallback>> devTrustChangeCallback_;
    std::map<std::string, std::shared_ptr<DeviceScreenStatusCallback>> deviceScreenStatusCallback_;
    std::map<std::string, std::shared_ptr<CredentialAuthStatusCallback>> credentialAuthStatusCallback_;
    std::map<std::string, std::shared_ptr<BindTargetCallback>> sinkBindTargetCallback_;
    std::mutex bindLock_;
    std::map<std::string, std::shared_ptr<GetDeviceProfileInfoListCallback>> getDeviceProfileInfoCallback_;
    std::map<std::string,
        std::map<std::string, std::set<std::shared_ptr<GetDeviceIconInfoCallback>>>> getDeviceIconInfoCallback_;
    std::map<std::string, std::shared_ptr<SetLocalDeviceNameCallback>> setLocalDeviceNameCallback_;
    std::map<std::string,
        std::map<std::string, std::shared_ptr<SetRemoteDeviceNameCallback>>> setRemoteDeviceNameCallback_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_NOTIFY_H
