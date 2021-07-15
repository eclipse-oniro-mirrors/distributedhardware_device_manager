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

#include "device_manager.h"

#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "device_manager_errno.h"
#include "device_manager_log.h"

namespace OHOS {
namespace DistributedHardware {
IMPLEMENT_SINGLE_INSTANCE(DeviceManager);

int32_t DeviceManager::InitDeviceManagerService()
{
    HILOGI("DeviceManager::InitDeviceManagerService start");
    if (dmInterface_ != nullptr) {
        HILOGI("DeviceManagerService Already Init");
        return ERR_OK;
    }

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        HILOGE("Get SystemAbilityManager Failed");
        return ERR_NO_INIT;
    }

    auto object = samgr->CheckSystemAbility(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
    if (object == nullptr) {
        HILOGE("Get DeviceManager SystemAbility Failed");
        return ERR_DEVICEMANAGER_SERVICE_NOT_READY;
    }

    if (dmRecipient_ == nullptr) {
        dmRecipient_ = sptr<DmDeathRecipient>(new DmDeathRecipient());
    }

    if (!object->AddDeathRecipient(dmRecipient_)) {
        HILOGE("InitDeviceManagerService: AddDeathRecipient Failed");
    }

    dmInterface_ = iface_cast<IDeviceManager>(object);
    HILOGI("DeviceManager::InitDeviceManagerService completed");
    return ERR_OK;
}

bool DeviceManager::IsInit(std::string &packageName)
{
    if (dmInterface_ == nullptr) {
        HILOGE("DeviceManager not Init");
        return false;
    }

    if (dmListener_.find(packageName) == dmListener_.end()) {
        HILOGE("dmListener_ not Init for %{public}s", packageName.c_str());
        return false;
    }
    return true;
}

int32_t DeviceManager::InitDeviceManager(std::string &packageName, std::shared_ptr<DmInitCallback> dmInitCallback)
{
    HILOGI("DeviceManager::InitDeviceManager start, packageName: %{public}s", packageName.c_str());
    if (packageName.empty() || dmInitCallback == nullptr) {
        HILOGE("InitDeviceManager error: Invalid parameter");
        return ERR_INVALID_VALUE;
    }

    HILOGI("InitDeviceManager in, packageName %{public}s", packageName.c_str());
    std::lock_guard<std::mutex> autoLock(lock_);
    int32_t ret = InitDeviceManagerService();
    if (ret != ERR_OK) {
        HILOGE("InitDeviceManager Failed with ret %{public}d", ret);
        return ret;
    }

    auto iter = dmListener_.find(packageName);
    if (iter != dmListener_.end()) {
        HILOGI("dmListener_ Already Init");
        dmInitCallback_[packageName] = dmInitCallback;
        return ERR_OK;
    }

    sptr<DeviceManagerListenerStub> listener = sptr<DeviceManagerListenerStub>(new DeviceManagerListenerStub());
    ret = dmInterface_->RegisterDeviceManagerListener(packageName, listener);
    if (ret != ERR_OK) {
        HILOGE("InitDeviceManager: RegisterDeviceManagerListener Failed with ret %{public}d", ret);
        return ret;
    }

    dmListener_[packageName] = listener;
    dmInitCallback_[packageName] = dmInitCallback;

    HILOGI("DeviceManager::InitDeviceManager completed, packageName: %{public}s", packageName.c_str());
    return ERR_OK;
}

int32_t DeviceManager::UnInitDeviceManager(std::string &packageName)
{
    HILOGI("DeviceManager::UnInitDeviceManager start, packageName: %{public}s", packageName.c_str());
    if (packageName.empty()) {
        HILOGE("InitDeviceManager error: Invalid parameter");
        return ERR_INVALID_VALUE;
    }

    HILOGI("UnInitDeviceManager in, packageName %{public}s", packageName.c_str());
    std::lock_guard<std::mutex> autoLock(lock_);
    if (dmInterface_ == nullptr) {
        HILOGE("DeviceManager not Init");
        return ERR_NO_INIT;
    }

    auto iter = dmListener_.find(packageName);
    if (iter != dmListener_.end()) {
        int32_t ret = dmInterface_->UnRegisterDeviceManagerListener(packageName);
        if (ret != ERR_OK) {
            HILOGE("UnInitDeviceManager: UnRegisterDeviceManagerListener Failed with ret %{public}d", ret);
            return ret;
        }
        dmListener_.erase(packageName);
        dmInitCallback_.erase(packageName);
    }

    if (dmListener_.empty()) {
        dmRecipient_ = nullptr;
        dmInterface_ = nullptr;
    }
    HILOGI("DeviceManager::UnInitDeviceManager completed, packageName: %{public}s", packageName.c_str());
    return ERR_OK;
}

int32_t DeviceManager::GetTrustedDeviceList(std::string &packageName, std::string &extra,
    std::vector<DmDeviceInfo> &deviceList)
{
    HILOGI("DeviceManager::GetTrustedDeviceList start, packageName: %{public}s", packageName.c_str());
    if (packageName.empty()) {
        HILOGE("Invalid para");
        return ERR_INVALID_VALUE;
    }

    if (!IsInit(packageName)) {
        HILOGE("DeviceManager not Init for %{public}s", packageName.c_str());
        return ERR_NO_INIT;
    }

    HILOGI("GetTrustedDeviceList in, packageName %{public}s", packageName.c_str());
    int32_t ret = dmInterface_->GetTrustedDeviceList(packageName, extra, deviceList);
    if (ret != ERR_OK) {
        HILOGE("RegisterDevStateCallback Failed with ret %{public}d", ret);
        return ret;
    }
    HILOGI("DeviceManager::GetTrustedDeviceList completed, packageName: %{public}s", packageName.c_str());
    return ERR_OK;
}

int32_t DeviceManager::RegisterDevStateCallback(std::string &packageName, std::string &extra,
    std::shared_ptr<DeviceStateCallback> callback)
{
    HILOGI("DeviceManager::RegisterDevStateCallback start, packageName: %{public}s", packageName.c_str());
    if (packageName.empty() || callback == nullptr) {
        HILOGE("Invalid para");
        return ERR_INVALID_VALUE;
    }

    if (!IsInit(packageName)) {
        HILOGE("DeviceManager not Init for %{public}s", packageName.c_str());
        return ERR_NO_INIT;
    }

    HILOGI("RegisterDevStateCallback in, packageName %{public}s", packageName.c_str());
    int32_t ret = dmInterface_->RegisterDeviceStateCallback(packageName, extra);
    if (ret != ERR_OK) {
        HILOGE("RegisterDevStateCallback Failed with ret %{public}d", ret);
        return ret;
    }

    std::lock_guard<std::mutex> autoLock(lock_);
    dmListener_[packageName]->AddDeviceStateCallback(callback);
    HILOGI("DeviceManager::RegisterDevStateCallback completed, packageName: %{public}s", packageName.c_str());
    return ERR_OK;
}

int32_t DeviceManager::UnRegisterDevStateCallback(std::string &packageName)
{
    HILOGI("DeviceManager::UnRegisterDevStateCallback start, packageName: %{public}s", packageName.c_str());
    if (packageName.empty()) {
        HILOGE("Invalid para");
        return ERR_INVALID_VALUE;
    }

    if (!IsInit(packageName)) {
        HILOGE("DeviceManager not Init for %{public}s", packageName.c_str());
        return ERR_NO_INIT;
    }

    HILOGI("UnRegisterDevStateCallback in, packageName %{public}s", packageName.c_str());
    int32_t ret = dmInterface_->UnRegisterDeviceStateCallback(packageName);
    if (ret != ERR_OK) {
        HILOGE("UnRegisterDeviceStateCallback Failed with ret %{public}d", ret);
        return ret;
    }

    std::lock_guard<std::mutex> autoLock(lock_);
    dmListener_[packageName]->RemoveDeviceStateCallback();
    HILOGI("DeviceManager::UnRegisterDevStateCallback completed, packageName: %{public}s", packageName.c_str());
    return ERR_OK;
}

int32_t DeviceManager::StartDeviceDiscovery(std::string &packageName, DmSubscribeInfo &subscribeInfo,
    std::shared_ptr<DiscoverCallback> callback)
{
    HILOGI("DeviceManager::StartDeviceDiscovery start, packageName: %{public}s", packageName.c_str());
    if (packageName.empty() || callback == nullptr) {
        HILOGE("Invalid para");
        return ERR_INVALID_VALUE;
    }

    if (!IsInit(packageName)) {
        HILOGE("DeviceManager not Init for %{public}s", packageName.c_str());
        return ERR_NO_INIT;
    }

    HILOGI("StartDeviceDiscovery in, packageName %{public}s", packageName.c_str());
    {
        std::lock_guard<std::mutex> autoLock(lock_);
        dmListener_[packageName]->AddDiscoverCallback(subscribeInfo.subscribeId, callback);
    }
    int32_t ret = dmInterface_->StartDeviceDiscovery(packageName, subscribeInfo);
    if (ret != ERR_OK) {
        HILOGE("StartDeviceDiscovery Failed with ret %{public}d", ret);
        return ret;
    }

    HILOGI("DeviceManager::StartDeviceDiscovery completed, packageName: %{public}s", packageName.c_str());
    return ERR_OK;
}

int32_t DeviceManager::StopDeviceDiscovery(std::string &packageName, uint16_t subscribeId)
{
    HILOGI("DeviceManager::StopDeviceDiscovery start , packageName: %{public}s", packageName.c_str());
    if (packageName.empty()) {
        HILOGE("Invalid para");
        return ERR_INVALID_VALUE;
    }

    if (!IsInit(packageName)) {
        HILOGE("DeviceManager not Init for %{public}s", packageName.c_str());
        return ERR_NO_INIT;
    }

    HILOGI("StopDeviceDiscovery in, packageName %{public}s", packageName.c_str());
    int32_t ret = dmInterface_->StopDeviceDiscovery(packageName, subscribeId);
    if (ret != ERR_OK) {
        HILOGE("StopDeviceDiscovery Failed with ret %{public}d", ret);
        return ret;
    }

    std::lock_guard<std::mutex> autoLock(lock_);
    dmListener_[packageName]->RemoveDiscoverCallback(subscribeId);
    HILOGI("DeviceManager::StopDeviceDiscovery completed, packageName: %{public}s", packageName.c_str());
    return ERR_OK;
}

int32_t DeviceManager::AuthenticateDevice(std::string &packageName, const DmDeviceInfo &deviceInfo, std::string &extra,
    std::shared_ptr<AuthenticateCallback> callback)
{
    HILOGI("DeviceManager::AuthenticateDevice start , packageName: %{public}s", packageName.c_str());
    if (packageName.empty()) {
        HILOGE("Invalid para");
        return ERR_INVALID_VALUE;
    }

    if (!IsInit(packageName)) {
        HILOGE("DeviceManager not Init for %{public}s", packageName.c_str());
        return ERR_NO_INIT;
    }

    HILOGI("AuthenticateDevice in, packageName %{public}s", packageName.c_str());
    int32_t ret = dmInterface_->AuthenticateDevice(packageName, deviceInfo, extra);
    if (ret != ERR_OK) {
        HILOGE("AuthenticateDevice Failed with ret %{public}d", ret);
        return ret;
    }

    std::lock_guard<std::mutex> autoLock(lock_);
    dmListener_[packageName]->AddAuthenticateCallback(deviceInfo.deviceId, callback);
    HILOGI("DeviceManager::AuthenticateDevice completed, packageName: %{public}s", packageName.c_str());
    return ERR_OK;
}

void DmDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    (void)remote;
    HILOGW("DmDeathRecipient : OnRemoteDied");
    for (auto iter : DeviceManager::GetInstance().dmInitCallback_) {
        iter.second->OnRemoteDied();
    }
}
} // namespace DistributedHardware
} // namespace OHOS
