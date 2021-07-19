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

#include "device_manager_service.h"

#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability_definition.h"

#include "anonymous_string.h"
#include "device_manager_errno.h"
#include "device_manager_log.h"
#include "softbus_adapter.h"

#include "hichain_adapter.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    const int32_t THREAD_POOL_TASK_NUM = 1;
}

IMPLEMENT_SINGLE_INSTANCE(DeviceManagerService);

const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(&DeviceManagerService::GetInstance());

DeviceManagerService::DeviceManagerService() : SystemAbility(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID, true)
{
    registerToService_ = false;
    state_ = ServiceRunningState::STATE_NOT_START;
    hichainBindCallback_ = std::make_shared<HiChainBindCallback>();
}

void DeviceManagerService::OnStart()
{
    HILOGI("DeviceManagerService::OnStart start");
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        HILOGD("DeviceManagerService has already started.");
        return;
    }
    if (!Init()) {
        HILOGE("failed to init DeviceManagerService");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
}

bool DeviceManagerService::Init()
{
    HILOGI("DeviceManagerService::Init ready to init.");
    if (!registerToService_) {
        bool ret = Publish(this);
        if (!ret) {
            HILOGE("DeviceManagerService::Init Publish failed!");
            return false;
        }
        registerToService_ = true;
    }
    if (threadPool_.GetThreadsNum() == 0) {
        threadPool_.Start(THREAD_POOL_TASK_NUM);
    }
    RegisterDeviceStateListener();
    return true;
}

void DeviceManagerService::OnStop()
{
    HILOGI("DeviceManagerService::OnStop ready to stop service.");
    state_ = ServiceRunningState::STATE_NOT_START;
    registerToService_ = false;
}

ServiceRunningState DeviceManagerService::QueryServiceState() const
{
    return state_;
}

void DeviceManagerService::RegisterDeviceStateListener()
{
    auto registerFunc = []() {
        SoftbusAdapter::GetInstance().RegSoftBusDeviceStateListener();
        HichainAdapter::GetInstance().Init();
    };
    threadPool_.AddTask(registerFunc);
}

int32_t DeviceManagerService::RegisterDeviceManagerListener(std::string &packageName, sptr<IRemoteObject> listener)
{
    if (packageName.empty() || listener == nullptr) {
        HILOGE("Error: parameter invalid");
        return ERR_NULL_OBJECT;
    }

    HILOGI("In, packageName: %{public}s", packageName.c_str());
    std::lock_guard<std::mutex> autoLock(listenerLock_);
    auto iter = dmListener_.find(packageName);
    if (iter != dmListener_.end()) {
        HILOGI("RegisterDeviceManagerListener: listener already exists");
        return ERR_NONE;
    }

    sptr<AppDeathRecipient> appRecipient = sptr<AppDeathRecipient>(new AppDeathRecipient());
    if (!listener->AddDeathRecipient(appRecipient)) {
        HILOGE("RegisterDeviceManagerListener: AddDeathRecipient Failed");
    }
    dmListener_[packageName] = listener;
    appRecipient_[packageName] = appRecipient;
    return ERR_NONE;
}

int32_t DeviceManagerService::UnRegisterDeviceManagerListener(std::string &packageName)
{
    if (packageName.empty()) {
        HILOGE("Error: parameter invalid");
        return ERR_NULL_OBJECT;
    }

    HILOGI("In, packageName: %{public}s", packageName.c_str());
    std::lock_guard<std::mutex> autoLock(listenerLock_);
    auto listenerIter = dmListener_.find(packageName);
    if (listenerIter == dmListener_.end()) {
        HILOGI("UnRegisterDeviceManagerListener: listener not exists");
        return ERR_NONE;
    }

    auto recipientIter = appRecipient_.find(packageName);
    if (recipientIter == appRecipient_.end()) {
        HILOGI("UnRegisterDeviceManagerListener: appRecipient not exists");
        dmListener_.erase(packageName);
        return ERR_NONE;
    }

    auto listener = listenerIter->second;
    auto appRecipient = recipientIter->second;
    listener->RemoveDeathRecipient(appRecipient);
    appRecipient_.erase(packageName);
    dmListener_.erase(packageName);
    return ERR_NONE;
}

int32_t DeviceManagerService::RegisterDeviceStateCallback(std::string &packageName, std::string &extra)
{
    HILOGI("In, packageName: %{public}s", packageName.c_str());
    devStateCallbackParas_[packageName] = extra;
    return ERR_NONE;
}

int32_t DeviceManagerService::UnRegisterDeviceStateCallback(std::string &packageName)
{
    HILOGI("In, packageName: %{public}s", packageName.c_str());
    devStateCallbackParas_.erase(packageName);
    return ERR_NONE;
}

int32_t DeviceManagerService::GetTrustedDeviceList(std::string &packageName, std::string &extra,
    std::vector<DmDeviceInfo> &deviceList)
{
    HILOGI("In, packageName: %{public}s", packageName.c_str());
    return SoftbusAdapter::GetSoftbusTrustDevices(packageName, extra, deviceList);
}

int32_t DeviceManagerService::StartDeviceDiscovery(std::string &packageName, DmSubscribeInfo &subscribeInfo)
{
    HILOGI("In, packageName: %{public}s, subscribeId %{public}d", packageName.c_str(),
        (int32_t)subscribeInfo.subscribeId);
    return SoftbusAdapter::GetInstance().StartSoftbusDiscovery(packageName, subscribeInfo);
}

int32_t DeviceManagerService::StopDeviceDiscovery(std::string &packageName, uint16_t subscribeId)
{
    HILOGI("In, packageName: %{public}s, subscribeId %{public}d", packageName.c_str(), (int32_t)subscribeId);
    return SoftbusAdapter::GetInstance().StopSoftbusDiscovery(packageName, subscribeId);
}

int32_t DeviceManagerService::AuthenticateDevice(std::string &packageName, const DmDeviceInfo &deviceInfo,
    std::string &extra)
{
    (void)extra;

    std::string deviceId = deviceInfo.deviceId;
    if (SoftbusAdapter::IsDeviceOnLine(deviceId)) {
        HILOGI("AuthenticateDevice, deviceId is already in trusted list, return.");
        return ERR_DEVICEMANAGER_DEVICE_ALREADY_TRUSTED;
    }

    DeviceReqInfo devReqInfo;
    devReqInfo.deviceId = deviceId;
    HILOGI("AuthenticateDevice In, packageName: %{public}s, deviceId %{public}s", packageName.c_str(),
        GetAnonyString(deviceId).c_str());
    int32_t ret = SoftbusAdapter::GetInstance().GetConnectionIpAddr(deviceId, devReqInfo.ipAddr);
    if (ret != ERR_OK) {
        HILOGE("AuthenticateDevice Error: can not find ip by deviceId.");
        return ret;
    }

    authCallbackParas_[deviceId] = packageName;
    return HichainAdapter::GetInstance().Bind(devReqInfo, hichainBindCallback_, false);
}

const std::map<std::string, sptr<IRemoteObject>>& DeviceManagerService::GetDmListener()
{
    return dmListener_;
}

const sptr<IDeviceManagerListener> DeviceManagerService::GetDmListener(std::string packageName) const
{
    auto iter = dmListener_.find(packageName);
    if (iter == dmListener_.end()) {
        return nullptr;
    }
    auto remote = iter->second;
    sptr<IDeviceManagerListener> dmListener = iface_cast<IDeviceManagerListener>(remote);
    return dmListener;
}

void AppDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    HILOGW("AppDeathRecipient: OnRemoteDied");
    std::map<std::string, sptr<IRemoteObject>> listeners = DeviceManagerService::GetInstance().GetDmListener();
    std::string packageName;
    for (auto iter : listeners) {
        if (iter.second == remote.promote()) {
            packageName = iter.first;
            break;
        }
    }

    if (packageName.empty()) {
        HILOGE("AppDeathRecipient: OnRemoteDied, no packageName matched");
        return;
    }

    HILOGI("AppDeathRecipient: OnRemoteDied for %{public}s", packageName.c_str());
    DeviceManagerService::GetInstance().UnRegisterDeviceManagerListener(packageName);
}


void HiChainBindCallback::onBindSuccess(std::string deviceId, const char *returnData)
{
    (void)returnData;
    HILOGI("onBindSuccess, DM bind succeed, deviceId: %{public}s", GetAnonyString(deviceId).c_str());
    auto res = DeviceManagerService::GetInstance().authCallbackParas_;
    auto iter = res.find(deviceId);
    if (iter == res.end()) {
        HILOGE("onBindSuccess deviceInfo not found by deviceId.");
        return;
    }

    std::string packageName = iter->second;
    sptr<IDeviceManagerListener> dmListener = DeviceManagerService::GetInstance().GetDmListener(packageName);
    if (dmListener != nullptr) {
        dmListener->OnAuthResult(packageName, deviceId, DmBindStatus::STATE_BIND_SUCCESS, ERR_NONE);
    }

    int32_t ret = SoftbusAdapter::GetInstance().SoftbusJoinLnn(deviceId);
    HILOGI("onBindSuccess, DM bind succeed, joinlnn ret=%{public}d.", ret);
}

void HiChainBindCallback::onBindFailed(std::string deviceId, int32_t errorCode)
{
    HILOGI("onBindFailed, DM bind failed, deviceId: %{public}s, errorCode: %{public}d",
        GetAnonyString(deviceId).c_str(), errorCode);
    auto res = DeviceManagerService::GetInstance().authCallbackParas_;
    auto iter = res.find(deviceId);
    if (iter == res.end()) {
        HILOGE("onBindFailed deviceInfo not found by deviceId.");
        return;
    }

    std::string packageName = iter->second;
    sptr<IDeviceManagerListener> dmListener = DeviceManagerService::GetInstance().GetDmListener(packageName);

    dmListener->OnAuthResult(packageName, deviceId, DmBindStatus::STATE_BIND_FAILD, errorCode);
}
} // namespace DistributedHardware
} // namespace OHOS
