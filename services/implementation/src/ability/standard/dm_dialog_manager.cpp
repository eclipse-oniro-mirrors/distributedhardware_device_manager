/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "auth_message_processor.h"
#include "dm_anonymous.h"
#include "dm_constants.h"
#include "dm_log.h"
#include "nlohmann/json.hpp"
#include "parameter.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedHardware {
static constexpr int32_t INVALID_USERID = -1;
static constexpr int32_t MESSAGE_PARCEL_KEY_SIZE = 3;
static constexpr int32_t WINDOW_LEVEL_UPPER = 2;
static constexpr int32_t WINDOW_LEVEL_DEFAULT = 1;
const std::string CONNECT_PIN_DIALOG = "pinDialog";
const std::string DM_UI_BUNDLE_NAME = "com.ohos.devicemanagerui";
const std::string CONFIRM_ABILITY_NAME = "com.ohos.devicemanagerui.ConfirmUIExtAbility";
const std::string PIN_ABILITY_NAME = "com.ohos.devicemanagerui.PincodeUIExtAbility";
const std::string INPUT_ABILITY_NAME = "com.ohos.devicemanagerui.InputUIExtAbility";

std::string DmDialogManager::bundleName_ = "";
std::string DmDialogManager::abilityName_ = "";
std::string DmDialogManager::deviceName_ = "";
std::string DmDialogManager::appOperationStr_ = "";
std::string DmDialogManager::customDescriptionStr_ = "";
std::string DmDialogManager::targetDeviceName_ = "";
std::string DmDialogManager::pinCode_ = "";
std::string DmDialogManager::hostPkgLabel_ = "";
int32_t DmDialogManager::deviceType_ = -1;
DmDialogManager DmDialogManager::dialogMgr_;
sptr<OHOS::AAFwk::IAbilityConnection> DmDialogManager::dialogConnectionCallback_(
    new (std::nothrow) DialogAbilityConnection());

std::atomic<bool> DmDialogManager::isConnectSystemUI_(false);
sptr<IRemoteObject> g_remoteObject = nullptr;

DmDialogManager::DmDialogManager()
{
    LOGI("DmDialogManager constructor");
}

DmDialogManager::~DmDialogManager()
{
    LOGI("DmDialogManager destructor");
}

DmDialogManager &DmDialogManager::GetInstance()
{
    return dialogMgr_;
}

void DmDialogManager::ShowConfirmDialog(const std::string param)
{
    std::string deviceName = "";
    std::string appOperationStr = "";
    std::string customDescriptionStr = "";
    std::string hostPkgLabel = "";
    int32_t deviceType = -1;
    nlohmann::json jsonObject = nlohmann::json::parse(param, nullptr, false);
    if (!jsonObject.is_discarded()) {
        if (IsString(jsonObject, TAG_REQUESTER)) {
            deviceName = jsonObject[TAG_REQUESTER].get<std::string>();
        }
        if (IsString(jsonObject, TAG_APP_OPERATION)) {
            appOperationStr = jsonObject[TAG_APP_OPERATION].get<std::string>();
        }
        if (IsString(jsonObject, TAG_CUSTOM_DESCRIPTION)) {
            customDescriptionStr = jsonObject[TAG_CUSTOM_DESCRIPTION].get<std::string>();
        }
        if (IsInt32(jsonObject, TAG_LOCAL_DEVICE_TYPE)) {
            deviceType = jsonObject[TAG_LOCAL_DEVICE_TYPE].get<std::int32_t>();
        }
        if (IsString(jsonObject, TAG_HOST_PKGLABEL)) {
            hostPkgLabel = jsonObject[TAG_HOST_PKGLABEL].get<std::string>();
        }
    }

    bundleName_ = DM_UI_BUNDLE_NAME;
    abilityName_ = CONFIRM_ABILITY_NAME;
    deviceName_ = deviceName;
    appOperationStr_ = appOperationStr;
    customDescriptionStr_ = customDescriptionStr;
    deviceType_ = deviceType;
    hostPkgLabel_ = hostPkgLabel;
    ConnectExtension();
}

void DmDialogManager::ShowPinDialog(const std::string param)
{
    bundleName_ = DM_UI_BUNDLE_NAME;
    abilityName_ = PIN_ABILITY_NAME;
    pinCode_ = param;
    std::thread pinDilog([]() { ConnectExtension(); });
    int32_t ret = pthread_setname_np(pinDilog.native_handle(), CONNECT_PIN_DIALOG.c_str());
    if (ret != DM_OK) {
        LOGE("pinDilog setname failed.");
    }
    pinDilog.detach();
}

void DmDialogManager::ShowInputDialog(const std::string param)
{
    targetDeviceName_ = param;
    bundleName_ = DM_UI_BUNDLE_NAME;
    abilityName_ = INPUT_ABILITY_NAME;
    ConnectExtension();
}

void DmDialogManager::ConnectExtension()
{
    LOGI("DmDialogManager::ConnectExtension start.");
    if (isConnectSystemUI_.load() && dialogConnectionCallback_ != nullptr) {
        AppExecFwk::ElementName element;
        dialogConnectionCallback_->OnAbilityConnectDone(element, g_remoteObject, INVALID_USERID);
        LOGI("DmDialogManager::ConnectExtension dialog has been show.");
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

    LOGI("DmDialogManager::ConnectExtension abilityManager ConnectAbility begin.");
    auto ret = abilityManager->ConnectAbility(want, dialogConnectionCallback_, INVALID_USERID);
    if (ret != ERR_OK) {
        LOGE("ConnectExtensionAbility sceneboard failed.");
        bundleName = "com.ohos.systemui";
        abilityName = "com.ohos.systemui.dialog";
        want.SetElementName(bundleName, abilityName);
        ret = abilityManager->ConnectAbility(want, dialogConnectionCallback_, INVALID_USERID);
        if (ret != ERR_OK) {
            LOGE("ConnectExtensionAbility systemui failed.");
        }
    }
}

void DmDialogManager::DialogAbilityConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int resultCode)
{
    LOGI("OnAbilityConnectDone");
    std::unique_lock<std::mutex> lock(mutex_);
    if (remoteObject == nullptr) {
        LOGE("remoteObject is nullptr");
        return;
    }
    if (g_remoteObject == nullptr) {
        g_remoteObject = remoteObject;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInt32(MESSAGE_PARCEL_KEY_SIZE);
    data.WriteString16(u"bundleName");
    data.WriteString16(Str8ToStr16(DmDialogManager::GetBundleName()));
    data.WriteString16(u"abilityName");
    data.WriteString16(Str8ToStr16(DmDialogManager::GetAbilityName()));
    data.WriteString16(u"parameters");
    nlohmann::json param;
    param["ability.want.params.uiExtensionType"] = "sysDialog/common";
    param["sysDialogZOrder"] = WINDOW_LEVEL_DEFAULT;
    if (DmDialogManager::GetAbilityName() == INPUT_ABILITY_NAME) {
        param["sysDialogZOrder"] = WINDOW_LEVEL_UPPER;
    }
    param["pinCode"] = DmDialogManager::GetPinCode();
    param["deviceName"] = DmDialogManager::GetDeviceName();
    param["appOperationStr"] = DmDialogManager::GetAppOperationStr();
    param["customDescriptionStr"] = DmDialogManager::GetCustomDescriptionStr();
    param["deviceType"] = DmDialogManager::GetDeviceType();
    param[TAG_TARGET_DEVICE_NAME] = DmDialogManager::GetTargetDeviceName();
    param[TAG_HOST_PKGLABEL] = DmDialogManager::GetHostPkgLabel();
    std::string paramStr = param.dump();
    data.WriteString16(Str8ToStr16(paramStr));
    LOGI("show dm dialog is begin");
    const uint32_t cmdCode = 1;
    int32_t ret = remoteObject->SendRequest(cmdCode, data, reply, option);
    if (ret != ERR_OK) {
        LOGE("show dm dialog is failed: %{public}d", ret);
        return;
    }
    isConnectSystemUI_.store(true);
    LOGI("show dm dialog is success");
}

void DmDialogManager::DialogAbilityConnection::OnAbilityDisconnectDone(
    const AppExecFwk::ElementName& element, int resultCode)
{
    LOGI("OnAbilityDisconnectDone");
    std::lock_guard<std::mutex> lock(mutex_);
    isConnectSystemUI_.store(false);
}
}
}