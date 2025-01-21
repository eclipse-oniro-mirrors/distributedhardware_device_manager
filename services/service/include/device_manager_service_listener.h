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

#ifndef OHOS_DM_SERVICE_LISTENER_H
#define OHOS_DM_SERVICE_LISTENER_H

#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "dm_device_info.h"
#include "dm_device_profile_info.h"
#include "idevice_manager_service_listener.h"
#if !(defined(__LITEOS_M__) || defined(LITE_DEVICE))
#include "kv_adapter_manager.h"
#endif
#if !defined(__LITEOS_M__)
#include "ipc_notify_dmfa_result_req.h"
#include "ipc_server_listener.h"
#endif
#include "ipc_notify_device_state_req.h"

namespace OHOS {
namespace DistributedHardware {
class DeviceManagerServiceListener : public IDeviceManagerServiceListener {
public:
    DeviceManagerServiceListener() {};
    virtual ~DeviceManagerServiceListener() {};

    void OnDeviceStateChange(const ProcessInfo &processInfo, const DmDeviceState &state,
        const DmDeviceInfo &info) override;

    void OnDeviceFound(const ProcessInfo &processInfo, uint16_t subscribeId, const DmDeviceInfo &info) override;

    void OnDiscoveryFailed(const ProcessInfo &processInfo, uint16_t subscribeId, int32_t failedReason) override;

    void OnDiscoverySuccess(const ProcessInfo &processInfo, int32_t subscribeId) override;

    void OnPublishResult(const std::string &pkgName, int32_t publishId, int32_t publishResult) override;

    void OnAuthResult(const ProcessInfo &processInfo, const std::string &deviceId, const std::string &token,
        int32_t status, int32_t reason) override;

    void OnUiCall(const ProcessInfo &processInfo, std::string &paramJson) override;

    void OnCredentialResult(const ProcessInfo &processInfo, int32_t action, const std::string &resultInfo) override;

    void OnBindResult(const ProcessInfo &processInfo, const PeerTargetId &targetId, int32_t result,
        int32_t status, std::string content) override;

    void OnUnbindResult(const ProcessInfo &processInfo, const PeerTargetId &targetId, int32_t result,
        std::string content) override;

    void OnPinHolderCreate(const ProcessInfo &processInfo, const std::string &deviceId, DmPinType pinType,
        const std::string &payload) override;
    void OnPinHolderDestroy(const ProcessInfo &processInfo, DmPinType pinType, const std::string &payload) override;
    void OnCreateResult(const ProcessInfo &processInfo, int32_t result) override;
    void OnDestroyResult(const ProcessInfo &processInfo, int32_t result) override;
    void OnPinHolderEvent(const ProcessInfo &processInfo, DmPinHolderEvent event, int32_t result,
        const std::string &content) override;
    void OnDeviceTrustChange(const std::string &udid, const std::string &uuid, DmAuthForm authForm) override;
    void OnDeviceScreenStateChange(const ProcessInfo &processInfo, DmDeviceInfo &devInfo) override;
    void OnCredentialAuthStatus(const ProcessInfo &processInfo, const std::string &deviceList, uint16_t deviceTypeId,
                                int32_t errcode) override;
    void OnAppUnintall(const std::string &pkgName) override;
    void OnSinkBindResult(const ProcessInfo &processInfo, const PeerTargetId &targetId, int32_t result,
        int32_t status, std::string content) override;
    void OnProcessRemove(const ProcessInfo &processInfo) override;
    void OnDevStateCallbackAdd(const ProcessInfo &processInfo, const std::vector<DmDeviceInfo> &deviceList) override;
    void OnGetDeviceProfileInfoListResult(const ProcessInfo &processInfo,
        const std::vector<DmDeviceProfileInfo> &deviceProfileInfos, int32_t code) override;
    void OnGetDeviceIconInfoResult(const ProcessInfo &processInfo,
        const DmDeviceIconInfo &dmDeviceIconInfo, int32_t code) override;

private:
    void ConvertDeviceInfoToDeviceBasicInfo(const std::string &pkgName,
        const DmDeviceInfo &info, DmDeviceBasicInfo &deviceBasicInfo);
    void SetDeviceInfo(std::shared_ptr<IpcNotifyDeviceStateReq> pReq, const ProcessInfo &processInfo,
        const DmDeviceState &state, const DmDeviceInfo &deviceInfo, const DmDeviceBasicInfo &deviceBasicInfo);
    int32_t FillUdidAndUuidToDeviceInfo(const std::string &pkgName, DmDeviceInfo &dmDeviceInfo);
    void ProcessDeviceStateChange(const ProcessInfo &processInfo, const DmDeviceState &state, const DmDeviceInfo &info,
        const DmDeviceBasicInfo &deviceBasicInfo);
    void ProcessAppStateChange(const ProcessInfo &processInfo, const DmDeviceState &state,
        const DmDeviceInfo &info, const DmDeviceBasicInfo &deviceBasicInfo);
    void SetDeviceScreenInfo(std::shared_ptr<IpcNotifyDeviceStateReq> pReq, const ProcessInfo &processInfo,
        const DmDeviceInfo &deviceInfo);
    void RemoveOnlinePkgName(const DmDeviceInfo &info);
#if !(defined(__LITEOS_M__) || defined(LITE_DEVICE))
    int32_t ConvertUdidHashToAnoyAndSave(const std::string &pkgName, DmDeviceInfo &deviceInfo);
    int32_t ConvertUdidHashToAnoyDeviceId(const std::string &pkgName, const std::string &udidHash,
        std::string &anoyDeviceId);
#endif
    std::vector<ProcessInfo> GetWhiteListSAProcessInfo(DmCommonNotifyEvent dmCommonNotifyEvent);
    std::vector<ProcessInfo> GetNotifyProcessInfoByUserId(int32_t userId, DmCommonNotifyEvent dmCommonNotifyEvent);
    ProcessInfo DealBindProcessInfo(const ProcessInfo &processInfo);
    void ProcessDeviceOnline(const std::vector<ProcessInfo> &procInfoVec, const ProcessInfo &processInfo,
        const DmDeviceState &state, const DmDeviceInfo &info, const DmDeviceBasicInfo &deviceBasicInfo);
    void ProcessDeviceOffline(const std::vector<ProcessInfo> &procInfoVec, const ProcessInfo &processInfo,
        const DmDeviceState &state, const DmDeviceInfo &info, const DmDeviceBasicInfo &deviceBasicInfo);
    void ProcessDeviceInfoChange(const std::vector<ProcessInfo> &procInfoVec, const ProcessInfo &processInfo,
        const DmDeviceState &state, const DmDeviceInfo &info, const DmDeviceBasicInfo &deviceBasicInfo);
    void ProcessAppOnline(const std::vector<ProcessInfo> &procInfoVec, const ProcessInfo &processInfo,
        const DmDeviceState &state, const DmDeviceInfo &info, const DmDeviceBasicInfo &deviceBasicInfo);
    void ProcessAppOffline(const std::vector<ProcessInfo> &procInfoVec, const ProcessInfo &processInfo,
        const DmDeviceState &state, const DmDeviceInfo &info, const DmDeviceBasicInfo &deviceBasicInfo);
    void RemoveNotExistProcess();
private:
#if !defined(__LITEOS_M__)
    IpcServerListener ipcServerListener_;
    static std::mutex alreadyNotifyPkgNameLock_;
    static std::map<std::string, DmDeviceInfo> alreadyOnlinePkgName_;
    static std::unordered_set<std::string> highPriorityPkgNameSet_;
#endif
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_SERVICE_LISTENER_H