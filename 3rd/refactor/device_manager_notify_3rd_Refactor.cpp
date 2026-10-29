/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "device_manager_notify_3rd_Refactor.h"

#include <thread>

#include "dm_error_type_3rd.h"
#include "dm_log_3rd.h"
#include "ipc_skeleton.h"
#include "permission_manager_3rd.h"
#include "multiple_user_connector_3rd.h"

namespace OHOS {
namespace DistributedHardware {

DM_IMPLEMENT_SINGLE_INSTANCE_3RD(DeviceManagerNotify3rdRefactor);

void DeviceManagerNotify3rdRefactor::RegisterDeathRecipientCallback(const std::string &businessName,
    std::shared_ptr<DmInit3rdCallback> dmInitCallback)
{
    if (businessName.empty()) {
        LOGE("Invalid parameter, businessName is empty.");
        return;
    }
    if (dmInitCallback == nullptr) {
        LOGE("Invalid parameter, callback is nullptr.");
        return;
    }
    std::lock_guard<ffrt::mutex> autoLock(dmInit3rdCallbackLock_);
    CHECK_SIZE_VOID(dmInit3rdCallbackMap_);
    dmInit3rdCallbackMap_[businessName] = dmInitCallback;
}

void DeviceManagerNotify3rdRefactor::UnRegisterDeathRecipientCallback(const std::string &businessName)
{
    if (businessName.empty()) {
        LOGE("Invalid parameter, businessName is empty.");
        return;
    }
    std::lock_guard<ffrt::mutex> autoLock(dmInit3rdCallbackLock_);
    dmInit3rdCallbackMap_.erase(businessName);
}

std::map<std::string, std::shared_ptr<DmInit3rdCallback>> DeviceManagerNotify3rdRefactor::GetDmInit3rdCallback()
{
    std::lock_guard<ffrt::mutex> autoLock(dmInit3rdCallbackLock_);
    std::map<std::string, std::shared_ptr<DmInit3rdCallback>> currentDmInitCallback = dmInit3rdCallbackMap_;
    return currentDmInitCallback;
}

void DeviceManagerNotify3rdRefactor::OnRemoteDied()
{
    LOGW("OnRemoteDied");
    std::map<std::string, std::shared_ptr<DmInit3rdCallback>> dmInit3rdCallbackMap = GetDmInit3rdCallback();
    for (auto iter : dmInit3rdCallbackMap) {
        LOGI("OnRemoteDied, businessName:%{public}s", iter.first.c_str());
        if (iter.second != nullptr) {
            iter.second->OnRemoteDied();
        }
    }
}

ProcessInfo3rd DeviceManagerNotify3rdRefactor::BuildProcessInfo(const std::string &businessName)
{
    ProcessInfo3rd processInfo;
    processInfo.tokenId = static_cast<uint32_t>(OHOS::IPCSkeleton::GetSelfTokenID());
    processInfo.uid = getuid();
    processInfo.businessName = businessName;
    int32_t userId = MultipleUserConnector3rd::GetCurrentAccountUserID();
    processInfo.userId = userId;
    if (PermissionManager3rd::GetInstance().GetProcessNameByTokenId(
        processInfo.tokenId, processInfo.processName) != DM_OK) {
        LOGE("Get caller process name failed.");
    }
    return processInfo;
}

int32_t DeviceManagerNotify3rdRefactor::RegisterAuthCallback(const std::string &businessName,
    std::shared_ptr<DmAuthCallback> dmAuthCallback)
{
    if (businessName.empty()) {
        LOGE("Invalid parameter, businessName is empty.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    if (dmAuthCallback == nullptr) {
        LOGE("Invalid parameter, dmAuthCallback is nullptr.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    ProcessInfo3rd processInfo = BuildProcessInfo(businessName);
    if (processInfo.processName.empty()) {
        LOGE("BuildProcessInfo failed.");
        return ERR_DM_FAILED;
    }
    std::lock_guard<ffrt::mutex> autoLock(dmAuthCallbackLock_);
    dmAuthCallbackMap_[processInfo] = dmAuthCallback;
    LOGI("completed");
    return DM_OK;
}

int32_t DeviceManagerNotify3rdRefactor::UnRegisterAuthCallback(const std::string &businessName)
{
    if (businessName.empty()) {
        LOGE("Invalid parameter, businessName is empty.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    ProcessInfo3rd processInfo = BuildProcessInfo(businessName);
    if (processInfo.processName.empty()) {
        LOGE("BuildProcessInfo failed.");
        return ERR_DM_FAILED;
    }
    std::lock_guard<ffrt::mutex> autoLock(dmAuthCallbackLock_);
    if (dmAuthCallbackMap_.find(processInfo) == dmAuthCallbackMap_.end()) {
        LOGE("Invalid parameter, callback not found.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    dmAuthCallbackMap_.erase(processInfo);
    LOGI("completed");
    return DM_OK;
}

void DeviceManagerNotify3rdRefactor::OnAuthResult(const ProcessInfo3rd &processInfo, int32_t result, int32_t status,
    const std::string &authContent)
{
    std::shared_ptr<DmAuthCallback> tempCbk = nullptr;
    {
        std::lock_guard<ffrt::mutex> autoLock(dmAuthCallbackLock_);
        for (auto iter = dmAuthCallbackMap_.begin(); iter != dmAuthCallbackMap_.end();) {
            if (iter->first == processInfo) {
                tempCbk = iter->second;
                iter = dmAuthCallbackMap_.erase(iter);
            } else {
                ++iter;
            }
        }
    }
    if (tempCbk == nullptr) {
        LOGE("callback is nullptr.");
        return;
    }
    tempCbk->OnAuthResult(processInfo, result, status, authContent);
}

void DeviceManagerNotify3rdRefactor::OnAuthResult(const ProcessInfo3rd &processInfo, int32_t result, int32_t status,
    std::vector<TrustDeviceInfo3rd> &deviceInfos, const std::string &authContent)
{
    std::shared_ptr<DmAuthCallback> tempCbk = nullptr;
    {
        std::lock_guard<ffrt::mutex> autoLock(dmAuthCallbackLock_);
        for (auto iter = dmAuthCallbackMap_.begin(); iter != dmAuthCallbackMap_.end();) {
            if (iter->first == processInfo) {
                tempCbk = iter->second;
                iter = dmAuthCallbackMap_.erase(iter);
            } else {
                ++iter;
            }
        }
    }
    if (tempCbk == nullptr) {
        FreeDeviceInfos(deviceInfos);
        LOGE("callback is nullptr.");
        return;
    }
    tempCbk->OnAuthResult(processInfo, result, status, deviceInfos, authContent);
}

} // namespace DistributedHardware
} // namespace OHOS
