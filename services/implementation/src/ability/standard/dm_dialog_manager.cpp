/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include "dm_dialog_manager.h"

#include <pthread.h>
#include <thread>

#include "ability_manager_client.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "dm_ui_constants.h"
#include "dm_constants.h"
#include "dm_anonymous.h"
#include "dm_log.h"
#include "dm_crypto.h"
#include "parameter.h"
#include "dm_single_instance.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
constexpr int32_t MESSAGE_PARCEL_KEY_SIZE = 3;
constexpr int32_t WINDOW_LEVEL_UPPER = 2;
constexpr int32_t WINDOW_LEVEL_DEFAULT = 1;
constexpr int32_t PROXY_DEFAULT = 11;
constexpr const char* CONNECT_PIN_DIALOG = "pinDialog";
constexpr const char* DM_UI_BUNDLE_NAME = "com.ohos.devicemanagerui";
constexpr const char* CONFIRM_ABILITY_NAME = "com.ohos.devicemanagerui.ConfirmUIExtAbility";
constexpr const char* PIN_ABILITY_NAME = "com.ohos.devicemanagerui.PincodeUIExtAbility";
constexpr const char* TAG_SERVICE_TYPE = "serviceType";
constexpr const char* INPUT_ABILITY_NAME = "com.ohos.devicemanagerui.InputUIExtAbility";
constexpr uint32_t CLOSE_DIALOG_CMD_CODE = 3;
constexpr uint32_t SHOW_DIALOG_CMD_CODE = 1;
constexpr const char* TAG_USER_ID = "userId";
}
DM_IMPLEMENT_SINGLE_INSTANCE(DmDialogManager);

DmDialogManager *DmDialogManager::CreateSession(const DmUiSessionHost &host, void *connection)
{
    if (connection == nullptr || host.size != sizeof(DmUiSessionHost) || host.retire == nullptr ||
        host.submit == nullptr) {
        return nullptr;
    }
    auto session = new (std::nothrow) DmDialogManager;
    if (session != nullptr) {
        session->managedSession_ = true;
        session->sessionHost_ = host;
        session->dialogConnectionCallback_ =
            sptr<AAFwk::IAbilityConnection>(static_cast<AAFwk::IAbilityConnection *>(connection));
    }
    return session;
}

void DmDialogManager::DestroySession(DmDialogManager *session)
{
    delete session;
}

namespace {
sptr<AAFwk::IAbilityManager> GetSessionAbilityManager()
{
    auto manager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (manager == nullptr) {
        return nullptr;
    }
    auto remote = manager->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
    return remote == nullptr ? nullptr : iface_cast<AAFwk::IAbilityManager>(remote);
}
} // namespace

void DmDialogManager::RetireSession()
{
    sessionHost_.retire(sessionHost_.generation);
}

void DmDialogManager::ConnectSessionExtension()
{
    sptr<IRemoteObject> existing;
    sptr<AAFwk::IAbilityConnection> connection;
    int32_t userId;
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        if (sessionClosing_) {
            return;
        }
        existing = g_remoteObject;
        connection = dialogConnectionCallback_;
        userId = userId_;
        sessionRequested_ = true;
    }
    if (existing != nullptr) {
        OnAbilityConnectDone(AppExecFwk::ElementName(), existing, ERR_OK);
        return;
    }
    auto manager = GetSessionAbilityManager();
    if (manager == nullptr) {
        LOGE("UI session ability service unavailable");
        RetireSession();
        return;
    }
    AAFwk::Want want;
    want.SetElementName("com.ohos.sceneboard", "com.ohos.sceneboard.systemdialog");
    auto connect = [&manager, &want, &connection, userId]() {
        // Match the official three-argument ConnectAbility wrapper; keep proxy-side checks.
        return manager->ConnectAbilityCommon(want, connection, nullptr,
            AppExecFwk::ExtensionAbilityType::SERVICE, userId, false, 0, 0);
    };
    int32_t result = connect();
    if (result != ERR_OK) {
        want.SetElementName("com.ohos.systemui", "com.ohos.systemui.dialog");
        result = connect();
    }
    if (result != ERR_OK) {
        LOGE("UI session connect failed: %{public}d", result);
        RetireSession();
        return;
    }
    bool closing;
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        closing = sessionClosing_;
    }
    if (closing) {
        DisconnectSession();
    }
}

int32_t DmDialogManager::DisconnectSession()
{
    sptr<AAFwk::IAbilityConnection> connection;
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        connection = dialogConnectionCallback_;
    }
    auto manager = GetSessionAbilityManager();
    if (manager == nullptr || connection == nullptr) {
        LOGE("UI session cannot disconnect; retaining resources");
        return -1;
    }
    int32_t result = manager->DisconnectAbility(connection);
    if (result != ERR_OK) {
        LOGE("UI session disconnect failed: %{public}d; retaining resources", result);
    }
    return result;
}

int32_t DmDialogManager::CloseSession()
{
    sptr<IRemoteObject> remote;
    bool requested;
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        sessionClosing_ = true;
        remote = g_remoteObject;
        requested = sessionRequested_;
    }
    if (remote != nullptr) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;
        int32_t result = remote->SendRequest(CLOSE_DIALOG_CMD_CODE, data, reply, option);
        if (result != ERR_OK) {
            LOGW("UI close request returned: %{public}d; waiting for disconnect", result);
        }
    }
    if (!requested) {
        RetireSession();
        return ERR_OK;
    }
    return DisconnectSession();
}


DmDialogManager::DmDialogManager()
{
    LOGI("constructor");
}

DmDialogManager::~DmDialogManager()
{
    LOGI("destructor");
}

void DmDialogManager::ConfigLocalInfo(JsonObject& jsonObject)
{
    if (IsBool(jsonObject, PARAM_KEY_IS_PROXY_BIND)) {
        isProxyBind_ = jsonObject[PARAM_KEY_IS_PROXY_BIND].Get<bool>();
    }
    if (IsBool(jsonObject, PARAM_KEY_IS_SERVICE_BIND)) {
        isServiceBind_ = jsonObject[PARAM_KEY_IS_SERVICE_BIND].Get<bool>();
    }
    if (IsString(jsonObject, SERVICE_USER_DATA)) {
        serviceUserData_ = jsonObject[SERVICE_USER_DATA].Get<std::string>();
    }
    if (IsString(jsonObject, TITLE)) {
        title_ = jsonObject[TITLE].Get<std::string>();
    }
    if (IsInt32(jsonObject, TAG_USER_ID)) {
        userId_ = jsonObject[TAG_USER_ID].Get<std::int32_t>();
    }
}

void DmDialogManager::ShowServiceBindConfirmDialog(const std::string &param)
{
    std::string deviceName = "";
    std::string appOperationStr = "";
    std::string customDescriptionStr = "";
    std::string hostPkgLabel = "";
    int32_t deviceType = -1;
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        JsonObject jsonObject(param);
        if (!jsonObject.IsDiscarded()) {
            if (IsString(jsonObject, DmUiConstants::TAG_REQUESTER)) {
                deviceName = jsonObject[DmUiConstants::TAG_REQUESTER].Get<std::string>();
            }
            if (IsString(jsonObject, DmUiConstants::TAG_APP_OPERATION)) {
                appOperationStr = jsonObject[DmUiConstants::TAG_APP_OPERATION].Get<std::string>();
            }
            if (IsString(jsonObject, DmUiConstants::TAG_CUSTOM_DESCRIPTION)) {
                customDescriptionStr = jsonObject[DmUiConstants::TAG_CUSTOM_DESCRIPTION].Get<std::string>();
            }
            if (IsInt32(jsonObject, DmUiConstants::TAG_LOCAL_DEVICE_TYPE)) {
                deviceType = jsonObject[DmUiConstants::TAG_LOCAL_DEVICE_TYPE].Get<std::int32_t>();
            }
            if (IsString(jsonObject, DmUiConstants::TAG_HOST_PKGLABEL)) {
                hostPkgLabel = jsonObject[DmUiConstants::TAG_HOST_PKGLABEL].Get<std::string>();
            }
            ConfigLocalInfo(jsonObject);
        }

        bundleName_ = DM_UI_BUNDLE_NAME;
        abilityName_ = CONFIRM_ABILITY_NAME;
        deviceName_ = deviceName;
        appOperationStr_ = appOperationStr;
        customDescriptionStr_ = customDescriptionStr;
        deviceType_ = deviceType;
        hostPkgLabel_ = hostPkgLabel;
    }
    ConnectExtension();
}

void DmDialogManager::ShowConfirmDialog(const std::string &param)
{
    std::string deviceName = "";
    std::string appOperationStr = "";
    std::string customDescriptionStr = "";
    std::string hostPkgLabel = "";
    int32_t deviceType = -1;
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        JsonObject jsonObject(param);
        if (!jsonObject.IsDiscarded()) {
            if (IsString(jsonObject, DmUiConstants::TAG_REQUESTER)) {
                deviceName = jsonObject[DmUiConstants::TAG_REQUESTER].Get<std::string>();
            }
            if (IsString(jsonObject, DmUiConstants::TAG_APP_OPERATION)) {
                appOperationStr = jsonObject[DmUiConstants::TAG_APP_OPERATION].Get<std::string>();
            }
            if (IsString(jsonObject, DmUiConstants::TAG_CUSTOM_DESCRIPTION)) {
                customDescriptionStr = jsonObject[DmUiConstants::TAG_CUSTOM_DESCRIPTION].Get<std::string>();
            }
            if (IsInt32(jsonObject, DmUiConstants::TAG_LOCAL_DEVICE_TYPE)) {
                deviceType = jsonObject[DmUiConstants::TAG_LOCAL_DEVICE_TYPE].Get<std::int32_t>();
            }
            if (IsString(jsonObject, DmUiConstants::TAG_HOST_PKGLABEL)) {
                hostPkgLabel = jsonObject[DmUiConstants::TAG_HOST_PKGLABEL].Get<std::string>();
            }
            if (IsBool(jsonObject, PARAM_KEY_IS_PROXY_BIND)) {
                isProxyBind_ = jsonObject[PARAM_KEY_IS_PROXY_BIND].Get<bool>();
            }
            if (IsString(jsonObject, APP_USER_DATA)) {
                appUserData_ = jsonObject[APP_USER_DATA].Get<std::string>();
            }
            if (IsString(jsonObject, TITLE)) {
                title_ = jsonObject[TITLE].Get<std::string>();
            }
        }

        bundleName_ = DM_UI_BUNDLE_NAME;
        abilityName_ = CONFIRM_ABILITY_NAME;
        deviceName_ = deviceName;
        appOperationStr_ = appOperationStr;
        customDescriptionStr_ = customDescriptionStr;
        deviceType_ = deviceType;
        hostPkgLabel_ = hostPkgLabel;
    }
    ConnectExtension();
}

void DmDialogManager::ShowPinDialog(const std::string &param)
{
    LOGI("pinCode: %{public}s", GetAnonyString(param).c_str());
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        bundleName_ = DM_UI_BUNDLE_NAME;
        abilityName_ = PIN_ABILITY_NAME;
        pinCode_ = param;
    }
    if (managedSession_) {
        auto connect = [](void *context) { static_cast<DmDialogManager *>(context)->ConnectExtension(); };
        if (sessionHost_.submit(sessionHost_.generation, connect, this) != ERR_OK) {
            LOGW("PIN connection work was cancelled before dispatch");
        }
        return;
    }
    ffrt::submit([this]() { ConnectExtension(); },
        ffrt::task_attr().name(CONNECT_PIN_DIALOG));
}

void DmDialogManager::ShowInputDialog(const std::string &param)
{
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        targetDeviceName_ = param;
        bundleName_ = DM_UI_BUNDLE_NAME;
        abilityName_ = INPUT_ABILITY_NAME;
    }
    ConnectExtension();
}

void DmDialogManager::CloseDialog()
{
    if (managedSession_) {
        CloseSession();
        return;
    }
    LOGI("In");
    std::lock_guard<ffrt::mutex> lock(mutex_);
    if (g_remoteObject == nullptr) {
        LOGW("g_remoteObject is nullptr");
        isCloseDialog_.store(true);
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = g_remoteObject->SendRequest(CLOSE_DIALOG_CMD_CODE, data, reply, option);
    if (ret != ERR_OK) {
        LOGE("close dm dialog is failed: %{public}d", ret);
        return;
    }
}

//LCOV_EXCL_START
void DmDialogManager::ConnectExtension()
{
    if (managedSession_) {
        ConnectSessionExtension();
        return;
    }
    LOGI("start.");
    isCloseDialog_.store(false);
    if (isConnectSystemUI_.load() && dialogConnectionCallback_ != nullptr && g_remoteObject != nullptr) {
        AppExecFwk::ElementName element;
        OnAbilityConnectDone(element, g_remoteObject, userId_);
        LOGI("dialog has been show.");
        return;
    }
    AAFwk::Want want;
    std::string bundleName = "com.ohos.sceneboard";
    std::string abilityName = "com.ohos.sceneboard.systemdialog";
    want.SetElementName(bundleName, abilityName);
    auto abilityManager = AAFwk::AbilityManagerClient::GetInstance();
    if (abilityManager == nullptr) {
        LOGE("AbilityManagerClient is nullptr");
        return;
    }
    std::lock_guard<ffrt::mutex> lock(mutex_);
    if (dialogConnectionCallback_ == nullptr) {
        dialogConnectionCallback_ = new (std::nothrow) DialogAbilityConnection();
    }
    if (dialogConnectionCallback_ == nullptr) {
        LOGE("create dialogConnectionCallback_ failed.");
        return;
    }
    LOGI("abilityManager ConnectAbility begin.");
    auto ret = abilityManager->ConnectAbility(want, dialogConnectionCallback_, userId_);
    if (ret != ERR_OK) {
        LOGE("ConnectExtensionAbility sceneboard failed.");
        bundleName = "com.ohos.systemui";
        abilityName = "com.ohos.systemui.dialog";
        want.SetElementName(bundleName, abilityName);
        ret = abilityManager->ConnectAbility(want, dialogConnectionCallback_, userId_);
        if (ret != ERR_OK) {
            LOGE("ConnectExtensionAbility systemui failed again.");
        }
    }
}
//LCOV_EXCL_STOP

void DmDialogManager::OnAbilityConnectDone(
    const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int resultCode)
{
    LOGI("start");
    if (managedSession_) {
        if (remoteObject == nullptr || resultCode != ERR_OK) {
            LOGE("UI connection completion failed: %{public}d", resultCode);
            RetireSession();
            return;
        }
        bool closing;
        {
            std::lock_guard<ffrt::mutex> lock(mutex_);
            g_remoteObject = remoteObject;
            isConnectSystemUI_.store(true);
            closing = sessionClosing_;
            if (!closing) {
                SendMsgRequest(remoteObject);
            }
        }
        if (closing) {
            DisconnectSession();
        }
        return;
    }
    std::lock_guard<ffrt::mutex> lock(mutex_);
    if (remoteObject == nullptr) {
        LOGE("remoteObject is nullptr");
        return;
    }
    if (g_remoteObject == nullptr) {
        g_remoteObject = remoteObject;
    }
    isConnectSystemUI_.store(true);
    if (isCloseDialog_.load()) {
        LOGW("isCloseDialog_  is true");
        isCloseDialog_.store(false);
        return;
    }
    SendMsgRequest(remoteObject);
}

void DmDialogManager::SendMsgRequest(const sptr<IRemoteObject>& remoteObject)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInt32(MESSAGE_PARCEL_KEY_SIZE);
    data.WriteString16(u"bundleName");
    data.WriteString16(Str8ToStr16(bundleName_));
    data.WriteString16(u"abilityName");
    data.WriteString16(Str8ToStr16(abilityName_));
    data.WriteString16(u"parameters");
    JsonObject param;
    param["ability.want.params.uiExtensionType"] = "sysDialog/common";
    param["sysDialogZOrder"] = WINDOW_LEVEL_DEFAULT;
    if (abilityName_ == INPUT_ABILITY_NAME) {
        param["sysDialogZOrder"] = WINDOW_LEVEL_UPPER;
    }
    param["isProxyBind"] = isProxyBind_;
    param["isServiceBind"] = isServiceBind_;
    param["appUserData"] = appUserData_;
    param["serviceUserData"] = serviceUserData_;
    param["title"] = title_;
    std::string pinCodeHash = GetAnonyString(Crypto::Sha256(pinCode_));
    LOGI("OnAbilityConnectDone pinCodeHash: %{public}s", pinCodeHash.c_str());
    param["pinCode"] = pinCode_;
    param["deviceName"] = deviceName_;
    param["appOperationStr"] = appOperationStr_;
    param["customDescriptionStr"] = customDescriptionStr_;
    param["deviceType"] = deviceType_;
    param["serviceType"] = serviceType_;
    param[TAG_TARGET_DEVICE_NAME] = targetDeviceName_;
    param[DmUiConstants::TAG_HOST_PKGLABEL] = hostPkgLabel_;
    param["disableUpGesture"] = 1;
    param["metaType"] = PROXY_DEFAULT;
    std::string paramStr = param.Dump();
    data.WriteString16(Str8ToStr16(paramStr));
    LOGI("show dm dialog is begin");
    int32_t ret = remoteObject->SendRequest(SHOW_DIALOG_CMD_CODE, data, reply, option);
    if (ret != ERR_OK) {
        LOGE("show dm dialog is failed: %{public}d", ret);
        return;
    }
    LOGI("show dm dialog is success");
}

void DmDialogManager::OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int resultCode)
{
    LOGI("start");
    if (managedSession_) {
        if (resultCode != ERR_OK && resultCode != DM_UI_TARGET_TERMINATED) {
            LOGE("UI disconnect completion failed: %{public}d", resultCode);
            return;
        }
        {
            std::lock_guard<ffrt::mutex> lock(mutex_);
            g_remoteObject = nullptr;
            isConnectSystemUI_.store(false);
            sessionRequested_ = false;
            sessionClosing_ = false;
        }
        RetireSession();
        return;
    }
    std::lock_guard<ffrt::mutex> lock(mutex_);
    g_remoteObject = nullptr;
    isConnectSystemUI_.store(false);
    isCloseDialog_.store(false);
}

void DmDialogManager::DialogAbilityConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int resultCode)
{
    DmDialogManager::GetInstance().OnAbilityConnectDone(element, remoteObject, resultCode);
}

void DmDialogManager::DialogAbilityConnection::OnAbilityDisconnectDone(
    const AppExecFwk::ElementName& element, int resultCode)
{
    DmDialogManager::GetInstance().OnAbilityDisconnectDone(element, resultCode);
}
}
}
