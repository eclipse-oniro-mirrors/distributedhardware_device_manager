/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "device_manager_service_impl.h"

#include <functional>

#include "app_manager.h"
#include "dm_anonymous.h"
#include "dm_constants.h"
#include "dm_crypto.h"
#include "dm_distributed_hardware_load.h"
#include "dm_log.h"
#include "dm_radar_helper.h"
#include "dm_softbus_cache.h"
#include "multiple_user_connector.h"
#if !(defined(__LITEOS_M__) || defined(LITE_DEVICE))
#include "dm_common_event_manager.h"
#include "parameter.h"
#include "common_event_support.h"
using namespace OHOS::EventFwk;
#endif

namespace OHOS {
namespace DistributedHardware {
DeviceManagerServiceImpl::DeviceManagerServiceImpl()
{
    LOGI("DeviceManagerServiceImpl constructor");
}

DeviceManagerServiceImpl::~DeviceManagerServiceImpl()
{
    LOGI("DeviceManagerServiceImpl destructor");
}

int32_t DeviceManagerServiceImpl::Initialize(const std::shared_ptr<IDeviceManagerServiceListener> &listener)
{
    LOGI("DeviceManagerServiceImpl Initialize");
    if (softbusConnector_ == nullptr) {
        softbusConnector_ = std::make_shared<SoftbusConnector>();
    }
    if (hiChainConnector_ == nullptr) {
        hiChainConnector_ = std::make_shared<HiChainConnector>();
    }
    if (mineHiChainConnector_ == nullptr) {
        mineHiChainConnector_ = std::make_shared<MineHiChainConnector>();
    }
    if (discoveryMgr_ == nullptr) {
        discoveryMgr_ = std::make_shared<DmDiscoveryManager>(softbusConnector_, listener, hiChainConnector_);
    }
    if (publishMgr_ == nullptr) {
        publishMgr_ = std::make_shared<DmPublishManager>(softbusConnector_, listener);
    }
    if (hiChainAuthConnector_ == nullptr) {
        hiChainAuthConnector_ = std::make_shared<HiChainAuthConnector>();
    }
    if (deviceStateMgr_ == nullptr) {
        deviceStateMgr_ = std::make_shared<DmDeviceStateManager>(softbusConnector_, listener,
                                                                 hiChainConnector_, hiChainAuthConnector_);
        deviceStateMgr_->RegisterSoftbusStateCallback();
    }
    if (authMgr_ == nullptr) {
        authMgr_ = std::make_shared<DmAuthManager>(softbusConnector_, hiChainConnector_, listener,
            hiChainAuthConnector_);
        softbusConnector_->GetSoftbusSession()->RegisterSessionCallback(authMgr_);
        hiChainConnector_->RegisterHiChainCallback(authMgr_);
        hiChainAuthConnector_->RegisterHiChainAuthCallback(authMgr_);
    }
    if (credentialMgr_ == nullptr) {
        credentialMgr_ = std::make_shared<DmCredentialManager>(hiChainConnector_, listener);
    }
    listener_ = listener;
    LOGI("Init success, singleton initialized");
    return DM_OK;
}

void DeviceManagerServiceImpl::Release()
{
    LOGI("DeviceManagerServiceImpl Release");
#if !(defined(__LITEOS_M__) || defined(LITE_DEVICE))
    commonEventManager_ = nullptr;
#endif
    softbusConnector_->GetSoftbusSession()->UnRegisterSessionCallback();
    hiChainConnector_->UnRegisterHiChainCallback();
    authMgr_ = nullptr;
    deviceStateMgr_ = nullptr;
    discoveryMgr_ = nullptr;
    publishMgr_ = nullptr;
    softbusConnector_ = nullptr;
    abilityMgr_ = nullptr;
    hiChainConnector_ = nullptr;
}

int32_t DeviceManagerServiceImpl::StartDeviceDiscovery(const std::string &pkgName, const DmSubscribeInfo &subscribeInfo,
    const std::string &extra)
{
    if (pkgName.empty()) {
        LOGE("StartDeviceDiscovery failed, pkgName is empty");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    return discoveryMgr_->StartDeviceDiscovery(pkgName, subscribeInfo, extra);
}

int32_t DeviceManagerServiceImpl::StartDeviceDiscovery(const std::string &pkgName, const uint16_t subscribeId,
    const std::string &filterOptions)
{
    if (pkgName.empty()) {
        LOGE("StartDeviceDiscovery failed, pkgName is empty");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    return discoveryMgr_->StartDeviceDiscovery(pkgName, subscribeId, filterOptions);
}

int32_t DeviceManagerServiceImpl::StopDeviceDiscovery(const std::string &pkgName, uint16_t subscribeId)
{
    if (pkgName.empty()) {
        LOGE("StopDeviceDiscovery failed, pkgName is empty");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    return discoveryMgr_->StopDeviceDiscovery(pkgName, subscribeId);
}

int32_t DeviceManagerServiceImpl::PublishDeviceDiscovery(const std::string &pkgName, const DmPublishInfo &publishInfo)
{
    if (pkgName.empty()) {
        LOGE("PublishDeviceDiscovery failed, pkgName is empty");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    return publishMgr_->PublishDeviceDiscovery(pkgName, publishInfo);
}

int32_t DeviceManagerServiceImpl::UnPublishDeviceDiscovery(const std::string &pkgName, int32_t publishId)
{
    if (pkgName.empty()) {
        LOGE("UnPublishDeviceDiscovery failed, pkgName is empty");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    return publishMgr_->UnPublishDeviceDiscovery(pkgName, publishId);
}

int32_t DeviceManagerServiceImpl::UnAuthenticateDevice(const std::string &pkgName, const std::string &udid,
    int32_t bindLevel)
{
    if (pkgName.empty() || udid.empty()) {
        LOGE("DeviceManagerServiceImpl::UnAuthenticateDevice failed, pkgName is %{public}s, udid is %{public}s",
            pkgName.c_str(), GetAnonyString(udid).c_str());
        return ERR_DM_INPUT_PARA_INVALID;
    }
    return authMgr_->UnAuthenticateDevice(pkgName, udid, bindLevel);
}

int32_t DeviceManagerServiceImpl::StopAuthenticateDevice(const std::string &pkgName)
{
    if (pkgName.empty()) {
        LOGE("DeviceManagerServiceImpl::StopAuthenticateDevice failed");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    return authMgr_->StopAuthenticateDevice(pkgName);
}

int32_t DeviceManagerServiceImpl::UnBindDevice(const std::string &pkgName, const std::string &udid,
    int32_t bindLevel)
{
    if (pkgName.empty() || udid.empty()) {
        LOGE("DeviceManagerServiceImpl::UnBindDevice failed, pkgName is %{public}s, udid is %{public}s",
            pkgName.c_str(), GetAnonyString(udid).c_str());
        return ERR_DM_INPUT_PARA_INVALID;
    }
    return authMgr_->UnBindDevice(pkgName, udid, bindLevel);
}

int32_t DeviceManagerServiceImpl::SetUserOperation(std::string &pkgName, int32_t action,
    const std::string &params)
{
    if (pkgName.empty() || params.empty()) {
        LOGE("DeviceManagerServiceImpl::SetUserOperation error: Invalid parameter, pkgName: %{public}s, extra:"
            "%{public}s", pkgName.c_str(), params.c_str());
        return ERR_DM_INPUT_PARA_INVALID;
    }
    if (authMgr_ != nullptr) {
        authMgr_->OnUserOperation(action, params);
    }
    return DM_OK;
}

void DeviceManagerServiceImpl::HandleOffline(DmDeviceState devState, DmDeviceInfo &devInfo)
{
    LOGI("DeviceManagerServiceImpl::HandleOffline");
    std::string trustDeviceId = deviceStateMgr_->GetUdidByNetWorkId(std::string(devInfo.networkId));
    LOGI("deviceStateMgr Udid: %{public}s", GetAnonyString(trustDeviceId).c_str());
    if (trustDeviceId == "") {
        LOGE("HandleOffline not get udid in deviceStateMgr.");
        return;
    }
    std::string udisHash = softbusConnector_->GetDeviceUdidHashByUdid(trustDeviceId);
    if (memcpy_s(devInfo.deviceId, DM_MAX_DEVICE_ID_LEN, udisHash.c_str(), udisHash.length()) != 0) {
        LOGE("get deviceId: %{public}s failed", GetAnonyString(udisHash).c_str());
        return;
    }
    char localUdid[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localUdid, DEVICE_UUID_LENGTH);
    std::string requestDeviceId = std::string(localUdid);
    std::map<int32_t, int32_t> userIdAndBindLevel =
        DeviceProfileConnector::GetInstance().GetUserIdAndBindLevel(requestDeviceId, trustDeviceId);
    ProcessInfo processInfo;
    processInfo.pkgName = std::string(DM_PKG_NAME);
    processInfo.userId = MultipleUserConnector::GetFirstForegroundUserId();
    for (const auto &item : userIdAndBindLevel) {
        if (item.second == INVALIED_TYPE) {
            LOGI("The offline device is identical account bind type.");
            devInfo.authForm = DmAuthForm::IDENTICAL_ACCOUNT;
            processInfo.userId = item.first;
            softbusConnector_->SetProcessInfo(processInfo);
        } else if (item.second == DEVICE) {
            LOGI("The offline device is device bind type.");
            devInfo.authForm = DmAuthForm::PEER_TO_PEER;
            processInfo.userId = item.first;
            softbusConnector_->SetProcessInfo(processInfo);
        } else if (item.second == SERVICE || item.second == APP) {
            LOGI("The offline device is APP_PEER_TO_PEER_TYPE bind type.");
            std::vector<ProcessInfo> processInfoVec =
                DeviceProfileConnector::GetInstance().GetProcessInfoFromAclByUserId(requestDeviceId, trustDeviceId,
                    item.first);
            softbusConnector_->SetProcessInfoVec(processInfoVec);
        }
        deviceStateMgr_->HandleDeviceStatusChange(devState, devInfo);
    }
}

void DeviceManagerServiceImpl::HandleOnline(DmDeviceState devState, DmDeviceInfo &devInfo)
{
    LOGI("DeviceManagerServiceImpl::HandleOnline");
    std::string trustDeviceId = "";
    if (softbusConnector_->GetUdidByNetworkId(devInfo.networkId, trustDeviceId) != DM_OK) {
        LOGE("HandleOnline get udid failed.");
        return;
    }
    std::string udisHash = softbusConnector_->GetDeviceUdidHashByUdid(trustDeviceId);
    if (memcpy_s(devInfo.deviceId, DM_MAX_DEVICE_ID_LEN, udisHash.c_str(), udisHash.length()) != 0) {
        LOGE("get deviceId: %{public}s failed", GetAnonyString(udisHash).c_str());
        return;
    }
    char localUdid[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localUdid, DEVICE_UUID_LENGTH);
    std::string requestDeviceId = std::string(localUdid);
    uint32_t bindType = DeviceProfileConnector::GetInstance().CheckBindType(trustDeviceId, requestDeviceId);
    LOGI("The online device bind type is %{public}d.", bindType);
    ProcessInfo processInfo;
    processInfo.pkgName = std::string(DM_PKG_NAME);
    processInfo.userId = MultipleUserConnector::GetFirstForegroundUserId();
    if (bindType == INVALIED_TYPE && isCredentialType_.load()) {
        PutIdenticalAccountToAcl(requestDeviceId, trustDeviceId);
        devInfo.authForm = DmAuthForm::IDENTICAL_ACCOUNT;
        isCredentialType_.store(false);
        softbusConnector_->SetProcessInfo(processInfo);
    } else if (bindType == IDENTICAL_ACCOUNT_TYPE) {
        devInfo.authForm = DmAuthForm::IDENTICAL_ACCOUNT;
        softbusConnector_->SetProcessInfo(processInfo);
    } else if (bindType == DEVICE_PEER_TO_PEER_TYPE) {
        devInfo.authForm = DmAuthForm::PEER_TO_PEER;
        softbusConnector_->SetProcessInfo(processInfo);
    } else if (bindType == DEVICE_ACROSS_ACCOUNT_TYPE) {
        devInfo.authForm = DmAuthForm::ACROSS_ACCOUNT;
        softbusConnector_->SetProcessInfo(processInfo);
    } else if (bindType == APP_PEER_TO_PEER_TYPE) {
        std::vector<ProcessInfo> processInfoVec =
            DeviceProfileConnector::GetInstance().GetProcessInfoFromAclByUserId(requestDeviceId, trustDeviceId,
                MultipleUserConnector::GetFirstForegroundUserId());
        softbusConnector_->SetProcessInfoVec(processInfoVec);
        devInfo.authForm = DmAuthForm::PEER_TO_PEER;
    } else if (bindType == APP_ACROSS_ACCOUNT_TYPE) {
        std::vector<ProcessInfo> processInfoVec =
            DeviceProfileConnector::GetInstance().GetProcessInfoFromAclByUserId(requestDeviceId, trustDeviceId,
                MultipleUserConnector::GetFirstForegroundUserId());
        softbusConnector_->SetProcessInfoVec(processInfoVec);
        devInfo.authForm = DmAuthForm::ACROSS_ACCOUNT;
    }
    LOGI("DeviceManagerServiceImpl::HandleOnline success devInfo auform %{public}d.", devInfo.authForm);
    deviceStateMgr_->HandleDeviceStatusChange(devState, devInfo);
}

void DeviceManagerServiceImpl::HandleDeviceStatusChange(DmDeviceState devState, DmDeviceInfo &devInfo)
{
    if (deviceStateMgr_ == nullptr) {
        LOGE("deviceStateMgr_ is nullpter!");
        return;
    }
    if (devState == DEVICE_STATE_ONLINE) {
        HandleOnline(devState, devInfo);
    } else if (devState == DEVICE_STATE_OFFLINE) {
        HandleOffline(devState, devInfo);
    } else {
        std::string udiddHash = GetUdidHashByNetworkId(devInfo.networkId);
        if (memcpy_s(devInfo.deviceId, DM_MAX_DEVICE_ID_LEN, udiddHash.c_str(), udiddHash.length()) != 0) {
            LOGE("get deviceId: %{public}s failed", GetAnonyString(udiddHash).c_str());
            return;
        }
        ProcessInfo processInfo;
        processInfo.pkgName = std::string(DM_PKG_NAME);
        processInfo.userId = MultipleUserConnector::GetFirstForegroundUserId();
        softbusConnector_->SetProcessInfo(processInfo);
        deviceStateMgr_->HandleDeviceStatusChange(devState, devInfo);
    }
}

std::string DeviceManagerServiceImpl::GetUdidHashByNetworkId(const std::string &networkId)
{
    if (softbusConnector_ == nullptr) {
        LOGE("softbusConnector_ is nullpter!");
        return "";
    }
    std::string udid = "";
    int32_t ret = softbusConnector_->GetUdidByNetworkId(networkId.c_str(), udid);
    if (ret != DM_OK) {
        LOGE("GetUdidByNetworkId failed ret: %{public}d", ret);
        return "";
    }
    return softbusConnector_->GetDeviceUdidHashByUdid(udid);
}

int DeviceManagerServiceImpl::OnSessionOpened(int sessionId, int result)
{
    std::string peerUdid = "";
    softbusConnector_->GetSoftbusSession()->GetPeerDeviceId(sessionId, peerUdid);
    struct RadarInfo info = {
        .funcName = "OnSessionOpened",
        .stageRes = static_cast<int32_t>(StageRes::STAGE_SUCC),
        .isTrust = static_cast<int32_t>(TrustStatus::NOT_TRUST),
        .peerUdid = peerUdid,
        .channelId = sessionId,
    };
    if (!DmRadarHelper::GetInstance().ReportAuthSessionOpenCb(info)) {
        LOGE("ReportAuthSessionOpenCb failed");
    }
    return SoftbusSession::OnSessionOpened(sessionId, result);
}

void DeviceManagerServiceImpl::OnSessionClosed(int sessionId)
{
    SoftbusSession::OnSessionClosed(sessionId);
}

void DeviceManagerServiceImpl::OnBytesReceived(int sessionId, const void *data, unsigned int dataLen)
{
    SoftbusSession::OnBytesReceived(sessionId, data, dataLen);
}

int32_t DeviceManagerServiceImpl::RequestCredential(const std::string &reqJsonStr, std::string &returnJsonStr)
{
    if (reqJsonStr.empty()) {
        LOGE("reqJsonStr is empty");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    if (credentialMgr_== nullptr) {
        LOGE("credentialMgr_ is nullptr");
        return ERR_DM_POINT_NULL;
    }
    return credentialMgr_->RequestCredential(reqJsonStr, returnJsonStr);
}

int32_t DeviceManagerServiceImpl::ImportCredential(const std::string &pkgName, const std::string &credentialInfo)
{
    if (pkgName.empty() || credentialInfo.empty()) {
        LOGE("DeviceManagerServiceImpl::ImportCredential failed, pkgName is %{public}s, credentialInfo is %{public}s",
            pkgName.c_str(), GetAnonyString(credentialInfo).c_str());
        return ERR_DM_INPUT_PARA_INVALID;
    }
    if (credentialMgr_== nullptr) {
        LOGE("credentialMgr_ is nullptr");
        return ERR_DM_POINT_NULL;
    }
    isCredentialType_.store(true);
    return credentialMgr_->ImportCredential(pkgName, credentialInfo);
}

int32_t DeviceManagerServiceImpl::DeleteCredential(const std::string &pkgName, const std::string &deleteInfo)
{
    if (pkgName.empty() || deleteInfo.empty()) {
        LOGE("DeviceManagerServiceImpl::DeleteCredential failed, pkgName is %{public}s, deleteInfo is %{public}s",
            pkgName.c_str(), GetAnonyString(deleteInfo).c_str());
        return ERR_DM_INPUT_PARA_INVALID;
    }
    if (credentialMgr_== nullptr) {
        LOGE("credentialMgr_ is nullptr");
        return ERR_DM_POINT_NULL;
    }
    isCredentialType_.store(false);
    return credentialMgr_->DeleteCredential(pkgName, deleteInfo);
}

int32_t DeviceManagerServiceImpl::MineRequestCredential(const std::string &pkgName, std::string &returnJsonStr)
{
    (void)pkgName;
    if (mineHiChainConnector_->RequestCredential(returnJsonStr) != DM_OK) {
        LOGE("failed to get device credential from hichain");
        return ERR_DM_HICHAIN_CREDENTIAL_REQUEST_FAILED;
    }
    return DM_OK;
}

int32_t DeviceManagerServiceImpl::CheckCredential(const std::string &pkgName, const std::string &reqJsonStr,
    std::string &returnJsonStr)
{
    (void)pkgName;
    if (reqJsonStr.empty()) {
        LOGE("reqJsonStr is empty");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    if (mineHiChainConnector_->CheckCredential(reqJsonStr, returnJsonStr) != DM_OK) {
        LOGE("failed to check devices credential status");
        return ERR_DM_HICHAIN_CREDENTIAL_CHECK_FAILED;
    }
    return DM_OK;
}

int32_t DeviceManagerServiceImpl::ImportCredential(const std::string &pkgName, const std::string &reqJsonStr,
    std::string &returnJsonStr)
{
    (void)pkgName;
    if (reqJsonStr.empty()) {
        LOGE("reqJsonStr is empty");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    if (mineHiChainConnector_->ImportCredential(reqJsonStr, returnJsonStr) != DM_OK) {
        LOGE("failed to import devices credential");
        return ERR_DM_HICHAIN_CREDENTIAL_IMPORT_FAILED;
    }
    isCredentialType_.store(true);
    return DM_OK;
}

int32_t DeviceManagerServiceImpl::DeleteCredential(const std::string &pkgName, const std::string &reqJsonStr,
    std::string &returnJsonStr)
{
    (void)pkgName;
    if (reqJsonStr.empty()) {
        LOGE("reqJsonStr is empty");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    if (mineHiChainConnector_->DeleteCredential(reqJsonStr, returnJsonStr) != DM_OK) {
        LOGE("failed to delete devices credential");
        return ERR_DM_HICHAIN_CREDENTIAL_DELETE_FAILED;
    }
    isCredentialType_.store(false);
    return DM_OK;
}

int32_t DeviceManagerServiceImpl::RegisterCredentialCallback(const std::string &pkgName)
{
    if (pkgName.empty()) {
        LOGE("RegisterCredentialCallback failed, pkgName is empty");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    if (credentialMgr_ == nullptr) {
        LOGE("credentialMgr_ is nullptr");
        return ERR_DM_POINT_NULL;
    }
    return credentialMgr_->RegisterCredentialCallback(pkgName);
}

int32_t DeviceManagerServiceImpl::UnRegisterCredentialCallback(const std::string &pkgName)
{
    if (pkgName.empty()) {
        LOGE("UnRegisterCredentialCallback failed, pkgName is empty");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    if (credentialMgr_== nullptr) {
        LOGE("credentialMgr_ is nullptr");
        return ERR_DM_POINT_NULL;
    }
    return credentialMgr_->UnRegisterCredentialCallback(pkgName);
}

int32_t DeviceManagerServiceImpl::RegisterUiStateCallback(const std::string &pkgName)
{
    if (pkgName.empty()) {
        LOGE("RegisterUiStateCallback failed, pkgName is empty");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    if (authMgr_ == nullptr) {
        LOGE("authMgr_ is nullptr");
        return ERR_DM_POINT_NULL;
    }
    return authMgr_->RegisterUiStateCallback(pkgName);
}

int32_t DeviceManagerServiceImpl::UnRegisterUiStateCallback(const std::string &pkgName)
{
    if (pkgName.empty()) {
        LOGE("UnRegisterUiStateCallback failed, pkgName is empty");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    if (authMgr_ == nullptr) {
        LOGE("authMgr_ is nullptr");
        return ERR_DM_POINT_NULL;
    }
    return authMgr_->UnRegisterUiStateCallback(pkgName);
}

int32_t DeviceManagerServiceImpl::PraseNotifyEventJson(const std::string &event, nlohmann::json &jsonObject)
{
    jsonObject = nlohmann::json::parse(event, nullptr, false);
    if (jsonObject.is_discarded()) {
        LOGE("event prase error.");
        return ERR_DM_FAILED;
    }
    if ((!jsonObject.contains("extra")) || (!jsonObject["extra"].is_object())) {
        LOGE("extra error");
        return ERR_DM_FAILED;
    }
    if ((!jsonObject["extra"].contains("deviceId")) || (!jsonObject["extra"]["deviceId"].is_string())) {
        LOGE("NotifyEvent deviceId invalid");
        return ERR_DM_FAILED;
    }
    return DM_OK;
}

int32_t DeviceManagerServiceImpl::NotifyEvent(const std::string &pkgName, const int32_t eventId,
    const std::string &event)
{
    LOGI("NotifyEvent begin, pkgName : %{public}s, eventId : %{public}d", pkgName.c_str(), eventId);
    if ((eventId <= DM_NOTIFY_EVENT_START) || (eventId >= DM_NOTIFY_EVENT_BUTT)) {
        LOGE("NotifyEvent eventId invalid");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    if (eventId == DM_NOTIFY_EVENT_ONDEVICEREADY) {
        nlohmann::json jsonObject;
        if (PraseNotifyEventJson(event, jsonObject) != DM_OK) {
            LOGE("NotifyEvent json invalid");
            return ERR_DM_INPUT_PARA_INVALID;
        }
        std::string deviceId;
        jsonObject["extra"]["deviceId"].get_to(deviceId);
        if (deviceStateMgr_== nullptr) {
            LOGE("deviceStateMgr_ is nullptr");
            return ERR_DM_POINT_NULL;
        }
        if (deviceStateMgr_->ProcNotifyEvent(eventId, deviceId) != DM_OK) {
            LOGE("NotifyEvent failed");
            return ERR_DM_INPUT_PARA_INVALID;
        };
    }
    return DM_OK;
}

int32_t DeviceManagerServiceImpl::GetGroupType(std::vector<DmDeviceInfo> &deviceList)
{
    LOGI("GetGroupType begin");
    if (softbusConnector_ == nullptr || hiChainConnector_ == nullptr) {
        LOGE("softbusConnector_ or hiChainConnector_ is nullptr");
        return ERR_DM_POINT_NULL;
    }

    for (auto it = deviceList.begin(); it != deviceList.end(); ++it) {
        std::string udid = "";
        int32_t ret = softbusConnector_->GetUdidByNetworkId(it->networkId, udid);
        if (ret != DM_OK) {
            LOGE("GetUdidByNetworkId failed ret: %{public}d", ret);
            return ret;
        }
        std::string deviceId = softbusConnector_->GetDeviceUdidHashByUdid(udid);
        if (memcpy_s(it->deviceId, DM_MAX_DEVICE_ID_LEN, deviceId.c_str(), deviceId.length()) != 0) {
            LOGE("get deviceId: %{public}s failed", GetAnonyString(deviceId).c_str());
        }
        it->authForm = hiChainConnector_->GetGroupType(udid);
    }
    return DM_OK;
}

int32_t DeviceManagerServiceImpl::GetUdidHashByNetWorkId(const char *networkId, std::string &deviceId)
{
    if (softbusConnector_ == nullptr || hiChainConnector_ == nullptr) {
        LOGE("softbusConnector_ or hiChainConnector_ is nullptr");
        return ERR_DM_POINT_NULL;
    }
    std::string udid = "";
    int32_t ret = softbusConnector_->GetUdidByNetworkId(networkId, udid);
    if (ret != DM_OK) {
        LOGE("GetUdidByNetworkId failed ret: %{public}d", ret);
        return ret;
    }
    deviceId = softbusConnector_->GetDeviceUdidHashByUdid(udid);
    return DM_OK;
}

int32_t DeviceManagerServiceImpl::ImportAuthCode(const std::string &pkgName, const std::string &authCode)
{
    if (pkgName.empty() || authCode.empty()) {
        LOGE("ImportAuthCode failed, pkgName or authCode is empty");
        return ERR_DM_INPUT_PARA_INVALID;
    }

    return authMgr_->ImportAuthCode(pkgName, authCode);
}

int32_t DeviceManagerServiceImpl::ExportAuthCode(std::string &authCode)
{
    int32_t ret = authMgr_->GeneratePincode();
    authCode = std::to_string(ret);
    LOGI("ExportAuthCode success, authCode: %{public}s.", GetAnonyString(authCode).c_str());
    return DM_OK;
}

int32_t DeviceManagerServiceImpl::BindTarget(const std::string &pkgName, const PeerTargetId &targetId,
    const std::map<std::string, std::string> &bindParam)
{
    if (pkgName.empty()) {
        LOGE("BindTarget failed, pkgName is empty");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    return authMgr_->BindTarget(pkgName, targetId, bindParam);
}

void DeviceManagerServiceImpl::PutIdenticalAccountToAcl(std::string requestDeviceId, std::string trustDeviceId)
{
    LOGI("DeviceManagerServiceImpl::PutIdenticalAccountAcl start.");
    char localDeviceId[DEVICE_UUID_LENGTH] = {0};
    Crypto::GetUdidHash(requestDeviceId, reinterpret_cast<uint8_t *>(localDeviceId));
    std::string localUdidHash = std::string(localDeviceId);
    DmAclInfo aclInfo;
    aclInfo.bindType = IDENTICAL_ACCOUNT;
    aclInfo.trustDeviceId = trustDeviceId;
    aclInfo.authenticationType = ALLOW_AUTH_ALWAYS;
    aclInfo.deviceIdHash = localUdidHash;
    DmAccesser accesser;
    accesser.requestUserId = MultipleUserConnector::GetFirstForegroundUserId();
    accesser.requestAccountId = MultipleUserConnector::GetOhosAccountIdByUserId(accesser.requestUserId);
    MultipleUserConnector::SetSwitchOldUserId(accesser.requestUserId);
    MultipleUserConnector::SetSwitchOldAccountId(accesser.requestAccountId);
    accesser.requestDeviceId = requestDeviceId;
    DmAccessee accessee;
    accessee.trustDeviceId = trustDeviceId;
    DeviceProfileConnector::GetInstance().PutAccessControlList(aclInfo, accesser, accessee);
}

int32_t DeviceManagerServiceImpl::DpAclAdd(const std::string &udid)
{
    LOGI("DeviceManagerServiceImpl DpAclAdd start.");
    MultipleUserConnector::SetSwitchOldUserId(MultipleUserConnector::GetCurrentAccountUserID());
    MultipleUserConnector::SetSwitchOldAccountId(MultipleUserConnector::GetOhosAccountId());
    if (deviceStateMgr_->CheckIsOnline(udid)) {
        LOGI("DeviceManagerServiceImpl DpAclAdd identical account and online");
        ProcessInfo processInfo;
        processInfo.pkgName = std::string(DM_PKG_NAME);
        processInfo.userId = MultipleUserConnector::GetFirstForegroundUserId();
        softbusConnector_->SetProcessInfo(processInfo);
        deviceStateMgr_->OnDeviceOnline(udid, DmAuthForm::IDENTICAL_ACCOUNT);
    }
    LOGI("DeviceManagerServiceImpl::DpAclAdd completed");
    return DM_OK;
}

int32_t DeviceManagerServiceImpl::IsSameAccount(const std::string &udid)
{
    if (udid.empty()) {
        LOGE("DeviceManagerServiceImpl::IsSameAccount error: udid: %{public}s", GetAnonyString(udid).c_str());
        return ERR_DM_INPUT_PARA_INVALID;
    }

    return DeviceProfileConnector::GetInstance().IsSameAccount(udid);
}

std::unordered_map<std::string, DmAuthForm> DeviceManagerServiceImpl::GetAppTrustDeviceIdList(
    std::string pkgname)
{
    char localDeviceId[DEVICE_UUID_LENGTH];
    GetDevUdid(localDeviceId, DEVICE_UUID_LENGTH);
    std::string deviceId = reinterpret_cast<char *>(localDeviceId);
    return DeviceProfileConnector::GetInstance().GetAppTrustDeviceList(pkgname, deviceId);
}

void DeviceManagerServiceImpl::LoadHardwareFwkService()
{
    DmDistributedHardwareLoad::GetInstance().LoadDistributedHardwareFwk();
}

void DeviceManagerServiceImpl::HandleIdentAccountLogout(const std::string &localUdid, int32_t localUserId,
    const std::string &peerUdid, int32_t peerUserId)
{
    LOGI("localUdid %{public}s, localUserId %{public}d, peerUdid %{public}s, peerUserId %{public}d.",
        GetAnonyString(localUdid).c_str(), localUserId, GetAnonyString(peerUdid).c_str(), peerUserId);
    bool notifyOffline = DeviceProfileConnector::GetInstance().DeleteAclForAccountLogOut(localUdid, localUserId,
        peerUdid, peerUserId);
    if (notifyOffline) {
        ProcessInfo processInfo;
        processInfo.pkgName = std::string(DM_PKG_NAME);
        processInfo.userId = localUserId;
        CHECK_NULL_VOID(softbusConnector_);
        softbusConnector_->SetProcessInfo(processInfo);
        CHECK_NULL_VOID(deviceStateMgr_);
        deviceStateMgr_->OnDeviceOffline(peerUdid);
    }
}

void DeviceManagerServiceImpl::HandleUserRemoved(int32_t preUserId)
{
    LOGI("PreUserId %{public}d.", preUserId);
    char localDeviceId[DEVICE_UUID_LENGTH];
    GetDevUdid(localDeviceId, DEVICE_UUID_LENGTH);
    std::string localUdid = reinterpret_cast<char *>(localDeviceId);
    DeviceProfileConnector::GetInstance().DeleteAclForUserRemoved(localUdid, preUserId);
    CHECK_NULL_VOID(hiChainConnector_);
    hiChainConnector_->DeleteAllGroup(preUserId);
}

void DeviceManagerServiceImpl::HandleRemoteUserRemoved(int32_t userId, const std::string &remoteUdid)
{
    LOGI("remoteUdid %{public}s, userId %{public}d", GetAnonyString(remoteUdid).c_str(), userId);
    DeviceProfileConnector::GetInstance().DeleteAclForUserRemoved(remoteUdid, userId);
    CHECK_NULL_VOID(hiChainConnector_);
    hiChainConnector_->DeleteAllGroup(userId);
}

void DeviceManagerServiceImpl::HandleUserSwitched(const std::map<std::string, int32_t> &deviceMap,
    int32_t currentUserId, int32_t beforeUserId)
{
    LOGI("currentUserId: %{public}s, beforeUserId: %{public}s", GetAnonyInt32(currentUserId).c_str(),
        GetAnonyInt32(beforeUserId).c_str());
    char localDeviceId[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localDeviceId, DEVICE_UUID_LENGTH);
    std::string localUdid = static_cast<std::string>(localDeviceId);
    DeviceProfileConnector::GetInstance().HandleUserSwitched(localUdid, currentUserId, beforeUserId);
}

void DeviceManagerServiceImpl::ScreenCommonEventCallback(std::string commonEventType)
{
    if (commonEventType == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED) {
        LOGI("DeviceManagerServiceImpl::ScreenCommonEventCallback on screen locked.");
        authMgr_->OnScreenLocked();
        return;
    }
    LOGI("DeviceManagerServiceImpl::ScreenCommonEventCallback error.");
}

int32_t DeviceManagerServiceImpl::CheckIsSameAccount(const DmAccessCaller &caller, const std::string &srcUdid,
    const DmAccessCallee &callee, const std::string &sinkUdid)
{
    return DeviceProfileConnector::GetInstance().CheckIsSameAccount(caller, srcUdid, callee, sinkUdid);
}

int32_t DeviceManagerServiceImpl::CheckAccessControl(const DmAccessCaller &caller, const std::string &srcUdid,
    const DmAccessCallee &callee, const std::string &sinkUdid)
{
    return DeviceProfileConnector::GetInstance().CheckAccessControl(caller, srcUdid, callee, sinkUdid);
}

void DeviceManagerServiceImpl::HandleDeviceNotTrust(const std::string &udid)
{
    LOGI("DeviceManagerServiceImpl::HandleDeviceNotTrust udid: %{public}s.", GetAnonyString(udid).c_str());
    if (udid.empty()) {
        LOGE("HandleDeviceNotTrust udid is empty.");
        return;
    }
    CHECK_NULL_VOID(authMgr_);
    authMgr_->HandleDeviceNotTrust(udid);
}

int32_t DeviceManagerServiceImpl::GetBindLevel(const std::string &pkgName, const std::string &localUdid,
    const std::string &udid, uint64_t &tokenId)
{
    return DeviceProfileConnector::GetInstance().GetBindLevel(pkgName, localUdid, udid, tokenId);
}

std::map<std::string, int32_t> DeviceManagerServiceImpl::GetDeviceIdAndBindLevel(int32_t userId)
{
    char localUdidTemp[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localUdidTemp, DEVICE_UUID_LENGTH);
    std::string localUdid = std::string(localUdidTemp);
    std::vector<int32_t> userIds;
    userIds.push_back(userId);
    return DeviceProfileConnector::GetInstance().GetDeviceIdAndBindLevel(userIds, localUdid);
}

std::multimap<std::string, int32_t> DeviceManagerServiceImpl::GetDeviceIdAndUserId(int32_t userId,
    const std::string &accountId)
{
    char localUdidTemp[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localUdidTemp, DEVICE_UUID_LENGTH);
    std::string localUdid = std::string(localUdidTemp);
    return DeviceProfileConnector::GetInstance().GetDeviceIdAndUserId(userId, accountId, localUdid);
}

void DeviceManagerServiceImpl::HandleAccountLogoutEvent(int32_t remoteUserId, const std::string &remoteAccountHash,
    const std::string &remoteUdid)
{
    char localUdidTemp[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localUdidTemp, DEVICE_UUID_LENGTH);
    std::string localUdid = std::string(localUdidTemp);
    std::multimap<std::string, int32_t> devIdAndUserMap =
        DeviceProfileConnector::GetInstance().GetDevIdAndUserIdByActHash(localUdid, remoteUdid,
            remoteUserId, remoteAccountHash);
    CHECK_NULL_VOID(listener_);
    std::string uuid = "";
    SoftbusCache::GetInstance().GetUuidByUdid(remoteUdid, uuid);
    listener_->OnDeviceTrustChange(remoteUdid, uuid, DmAuthForm::IDENTICAL_ACCOUNT);
    for (const auto &item : devIdAndUserMap) {
        bool notifyOffline = DeviceProfileConnector::GetInstance().DeleteAclForAccountLogOut(item.first, item.second,
            remoteUdid, remoteUserId);
        if (notifyOffline) {
            ProcessInfo processInfo;
            processInfo.pkgName = std::string(DM_PKG_NAME);
            processInfo.userId = item.second;
            CHECK_NULL_VOID(softbusConnector_);
            softbusConnector_->SetProcessInfo(processInfo);
            CHECK_NULL_VOID(deviceStateMgr_);
            deviceStateMgr_->OnDeviceOffline(remoteUdid);
        }
    }
}

DmAuthForm DeviceManagerServiceImpl::ConvertBindTypeToAuthForm(int32_t bindType)
{
    LOGI("BindType %{public}d.", bindType);
    DmAuthForm authForm = DmAuthForm::INVALID_TYPE;
    if (bindType == DM_IDENTICAL_ACCOUNT) {
        authForm = IDENTICAL_ACCOUNT;
    } else if (bindType == DM_POINT_TO_POINT) {
        authForm = PEER_TO_PEER;
    } else if (bindType == DM_ACROSS_ACCOUNT) {
        authForm = ACROSS_ACCOUNT;
    } else {
        LOGE("Invalied bindType.");
    }
    return authForm;
}

void DeviceManagerServiceImpl::HandleDevUnBindEvent(int32_t remoteUserId, const std::string &remoteUdid)
{
    char localUdidTemp[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localUdidTemp, DEVICE_UUID_LENGTH);
    std::string localUdid = std::string(localUdidTemp);
    int32_t bindType = DeviceProfileConnector::GetInstance().HandleDevUnBindEvent(remoteUserId, remoteUdid, localUdid);
    if (bindType == DM_INVALIED_BINDTYPE) {
        LOGE("Invalied bindtype.");
        return;
    }
    CHECK_NULL_VOID(authMgr_);
    authMgr_->DeleteGroup(DM_PKG_NAME, remoteUdid);
}

void DeviceManagerServiceImpl::HandleAppUnBindEvent(int32_t remoteUserId, const std::string &remoteUdid,
    int32_t tokenId)
{
    char localUdidTemp[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localUdidTemp, DEVICE_UUID_LENGTH);
    std::string localUdid = std::string(localUdidTemp);
    ProcessInfo processInfo =
        DeviceProfileConnector::GetInstance().HandleAppUnBindEvent(remoteUserId, remoteUdid, tokenId, localUdid);
    if (processInfo.pkgName.empty()) {
        LOGE("Pkgname is empty.");
        return;
    }
    CHECK_NULL_VOID(softbusConnector_);
    softbusConnector_->SetProcessInfo(processInfo);
    softbusConnector_->HandleDeviceOffline(remoteUdid);
}

void DeviceManagerServiceImpl::HandleSyncUserIdEvent(const std::vector<uint32_t> &foregroundUserIds,
    const std::vector<uint32_t> &backgroundUserIds, const std::string &remoteUdid)
{
    LOGI("remote udid: %{public}s, foregroundUserIds: %{public}s, backgroundUserIds: %{public}s",
        GetAnonyString(remoteUdid).c_str(), GetIntegerList<uint32_t>(foregroundUserIds).c_str(),
        GetIntegerList<uint32_t>(backgroundUserIds).c_str());
    char localUdidTemp[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localUdidTemp, DEVICE_UUID_LENGTH);
    std::string localUdid = std::string(localUdidTemp);
    std::vector<int32_t> rmtFrontUserIdsTemp(foregroundUserIds.begin(), foregroundUserIds.end());
    std::vector<int32_t> rmtBackUserIdsTemp(backgroundUserIds.begin(), backgroundUserIds.end());
    std::vector<int32_t> localUserIds;
    int32_t ret = MultipleUserConnector::GetForegroundUserIds(localUserIds);
    if (ret != DM_OK || localUserIds.empty()) {
        LOGE("Get foreground userids failed, ret: %{public}d", ret);
        return;
    }
    DeviceProfileConnector::GetInstance().UpdateACL(localUdid, localUserIds, remoteUdid,
        rmtFrontUserIdsTemp, rmtBackUserIdsTemp);
    DeviceProfileConnector::GetInstance().HandleSyncForegroundUserIdEvent(rmtFrontUserIdsTemp, remoteUdid,
        localUserIds, localUdid);
    DeviceProfileConnector::GetInstance().HandleSyncBackgroundUserIdEvent(rmtBackUserIdsTemp, remoteUdid,
        localUserIds, localUdid);
}

void DeviceManagerServiceImpl::HandleDeviceScreenStatusChange(DmDeviceInfo &devInfo)
{
    LOGI("In");
    CHECK_NULL_VOID(deviceStateMgr_);
    CHECK_NULL_VOID(softbusConnector_);
    std::string trustDeviceId = "";
    if (softbusConnector_->GetUdidByNetworkId(devInfo.networkId, trustDeviceId) != DM_OK) {
        LOGE("get udid failed.");
        return;
    }
    std::string udidHash = softbusConnector_->GetDeviceUdidHashByUdid(trustDeviceId);
    if (memcpy_s(devInfo.deviceId, DM_MAX_DEVICE_ID_LEN, udidHash.c_str(), udidHash.length()) != 0) {
        LOGE("get deviceId: %{public}s failed", GetAnonyString(udidHash).c_str());
        return;
    }
    char localUdid[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localUdid, DEVICE_UUID_LENGTH);
    std::string requestDeviceId = static_cast<std::string>(localUdid);
    uint32_t bindType = DeviceProfileConnector::GetInstance().CheckBindType(trustDeviceId, requestDeviceId);
    LOGI("bind type is %{public}d.", bindType);
    if (bindType == INVALIED_TYPE) {
        return;
    } else if (bindType == IDENTICAL_ACCOUNT_TYPE || bindType == DEVICE_PEER_TO_PEER_TYPE ||
        bindType == DEVICE_ACROSS_ACCOUNT_TYPE) {
        ProcessInfo processInfo;
        processInfo.pkgName = std::string(DM_PKG_NAME);
        processInfo.userId = MultipleUserConnector::GetFirstForegroundUserId();
        softbusConnector_->SetProcessInfo(processInfo);
    } else if (bindType == APP_PEER_TO_PEER_TYPE || bindType == APP_ACROSS_ACCOUNT_TYPE) {
        std::vector<ProcessInfo> processInfoVec =
            DeviceProfileConnector::GetInstance().GetProcessInfoFromAclByUserId(requestDeviceId, trustDeviceId,
                MultipleUserConnector::GetFirstForegroundUserId());
        softbusConnector_->SetProcessInfoVec(processInfoVec);
    }
    deviceStateMgr_->HandleDeviceScreenStatusChange(devInfo);
}

void DeviceManagerServiceImpl::HandleCredentialAuthStatus(const std::string &deviceList, uint16_t deviceTypeId,
                                                          int32_t errcode)
{
    CHECK_NULL_VOID(credentialMgr_);
    credentialMgr_->HandleCredentialAuthStatus(deviceList, deviceTypeId, errcode);
}

int32_t DeviceManagerServiceImpl::ProcessAppUnintall(const std::string &appId, int32_t accessTokenId)
{
    CHECK_NULL_RETURN(listener_, ERR_DM_POINT_NULL);
    std::vector<DistributedDeviceProfile::AccessControlProfile> profiles =
        DeviceProfileConnector::GetInstance().GetAllAccessControlProfile();
    LOGI("delete ACL size is %{public}zu, appId %{public}s", profiles.size(), GetAnonyString(appId).c_str());
    if (profiles.size() == 0) {
        return DM_OK;
    }
    std::vector<std::pair<int32_t, std::string>> delACLInfoVec;
    std::vector<int32_t> userIdVec;
    for (auto &item : profiles) {
        int64_t tokenId = item.GetAccesser().GetAccesserTokenId();
        if (accessTokenId != static_cast<int32_t>(tokenId)) {
            continue;
        }
        DeviceProfileConnector::GetInstance().DeleteAccessControlById(item.GetAccessControlId());
        listener_->OnAppUnintall(item.GetAccesser().GetAccesserBundleName());
        if (item.GetBindLevel() == DEVICE) {
            userIdVec.push_back(item.GetAccesser().GetAccesserUserId());
            delACLInfoVec.push_back(std::pair<int32_t, std::string>(item.GetAccesser().GetAccesserUserId(),
                item.GetAccessee().GetAccesseeDeviceId()));
        }
    }
    if (delACLInfoVec.size() == 0) {
        LOGI("delACLInfoVec is empty");
        return DM_OK;
    }
    if (userIdVec.size() == 0) {
        LOGI("userIdVec is empty");
        return DM_OK;
    }
    CHECK_NULL_RETURN(hiChainConnector_, ERR_DM_POINT_NULL);
    hiChainConnector_->DeleteGroupByACL(delACLInfoVec, userIdVec);
    return DM_OK;
}

std::multimap<std::string, int32_t> DeviceManagerServiceImpl::GetDeviceIdAndUserId(int32_t localUserId)
{
    LOGI("localUserId %{public}d.", localUserId);
    char localdeviceId[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localdeviceId, DEVICE_UUID_LENGTH);
    std::string localUdid = std::string(localdeviceId);
    return DeviceProfileConnector::GetInstance().GetDeviceIdAndUserId(localUdid, localUserId);
}

extern "C" IDeviceManagerServiceImpl *CreateDMServiceObject(void)
{
    return new DeviceManagerServiceImpl;
}
} // namespace DistributedHardware
} // namespace OHOS
