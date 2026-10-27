/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "multiple_user_connector.h"
#include "os_account_manager.h"

#include <cctype>
#include <cstdlib>
#include "dm_constants.h"
#include "dm_error_type.h"
#include "dm_auth_manager_base_refactor.h"
#include "power_mgr_client.h"
#if defined(SUPPORT_SCREENLOCK)
#include "screenlock_manager.h"
#endif

#ifdef OS_ACCOUNT_PART_EXISTS
#include "os_account_manager.h"
using namespace OHOS::AccountSA;
#endif // OS_ACCOUNT_PART_EXISTS

namespace OHOS {
namespace DistributedHardware {
const char* TAG_DMVERSION = "dmVersion";
const char* TAG_DM_VERSION_V2 = "dmVersionV2";
const char* TAG_EDITION = "edition";
const char* TAG_DATA = "data";
const char* TAG_DATA_LEN = "dataLen";
const char* TAG_BUNDLE_NAME = "bundleName";
const char* TAG_BUNDLE_NAME_V2 = "bundleNameV2";
const char* TAG_PEER_BUNDLE_NAME = "PEER_BUNDLE_NAME";
const char* TAG_PEER_BUNDLE_NAME_V2 = "PEER_BUNDLE_NAME_V2";
const char* TAG_PEER_PKG_NAME = "PEER_PKG_NAME";
const char* TAG_BIND_LEVEL = "bindLevel";
const char* TAG_REPLY = "REPLY";
const char* TAG_APP_THUMBNAIL2 = "appThumbnail";
const char* TAG_AUTH_FINISH = "isFinish";
const char* TAG_LOCAL_USERID = "localUserId";
const char* TAG_LOCAL_DEVICE_ID = "LOCALDEVICEID";
const char* TAG_IDENTICAL_ACCOUNT = "IDENTICALACCOUNT";
const char* TAG_ACCOUNT_GROUPID = "ACCOUNTGROUPID";
const char* TAG_HAVE_CREDENTIAL = "haveCredential";
const char* TAG_ISONLINE = "isOnline";
const char* TAG_AUTHED = "authed";
const char* TAG_LOCAL_ACCOUNTID = "localAccountId";
const char* TAG_TOKENID = "tokenId";
const char* TAG_HOST_PKGLABEL = "hostPkgLabel";
const char* TAG_REMOTE_DEVICE_NAME = "REMOTE_DEVICE_NAME";
const char* TAG_HOST = "HOST";
const char* TAG_PROXY_CONTEXT_ID = "proxyContextId";
const char* TAG_IS_NEED_AUTHENTICATE = "isNeedAuthenticate";
const char* APP_OPERATION_KEY = "appOperation";
const char* TARGET_PKG_NAME_KEY = "targetPkgName";
const char* CUSTOM_DESCRIPTION_KEY = "customDescription";
const char* CANCEL_DISPLAY_KEY = "cancelPinCodeDisplay";
const char* BUNDLE_NAME_KEY = "bundleName";

const char* AUTHENTICATE_TIMEOUT_TASK = "deviceManagerTimer:authenticate";
const char* NEGOTIATE_TIMEOUT_TASK = "deviceManagerTimer:negotiate";
const char* CONFIRM_TIMEOUT_TASK = "deviceManagerTimer:confirm";
const char* INPUT_TIMEOUT_TASK = "deviceManagerTimer:input";
const char* SESSION_HEARTBEAT_TIMEOUT_TASK = "deviceManagerTimer:sessionHeartbeat";
const char* WAIT_REQUEST_TIMEOUT_TASK = "deviceManagerTimer:waitRequest";
const char* AUTH_DEVICE_TIMEOUT_TASK = "deviceManagerTimer:authDevice_";
const char* WAIT_PIN_AUTH_TIMEOUT_TASK = "deviceManagerTimer:waitPinAuth";
const char* WAIT_NEGOTIATE_TIMEOUT_TASK = "deviceManagerTimer:waitNegotiate";
const char* GET_ULTRASONIC_PIN_TIMEOUT_TASK = "deviceManagerTimer:getUltrasonicPin";
const char* ADD_TIMEOUT_TASK = "deviceManagerTimer:add";
const char* WAIT_SESSION_CLOSE_TIMEOUT_TASK = "deviceManagerTimer:waitSessionClose";
const char* CLOSE_SESSION_TASK_SEPARATOR = "#";
const char* TAG_DM_CERT_CHAIN = "dmCertChain";
const char* TAG_CERT_COUNT = "certCount";
const char* TAG_CERT = "cert";
const char* TAG_IS_COMMON_FLAG = "isCommonFlag";
const char* TAG_CERT_RANDOM = "certRandom";

const int32_t AUTHENTICATE_TIMEOUT = 120;
const int32_t CONFIRM_TIMEOUT = 60;
const int32_t NEGOTIATE_TIMEOUT = 10;
const int32_t INPUT_TIMEOUT = 60;
const int32_t ADD_TIMEOUT = 10;
const int32_t WAIT_NEGOTIATE_TIMEOUT = 10;
const int32_t WAIT_REQUEST_TIMEOUT = 10;
const int32_t CLONE_AUTHENTICATE_TIMEOUT = 20;
const int32_t CLONE_CONFIRM_TIMEOUT = 10;
const int32_t CLONE_NEGOTIATE_TIMEOUT = 10;
const int32_t CLONE_ADD_TIMEOUT = 10;
const int32_t CLONE_WAIT_NEGOTIATE_TIMEOUT = 10;
const int32_t CLONE_WAIT_REQUEST_TIMEOUT = 10;
const int32_t CLONE_SESSION_HEARTBEAT_TIMEOUT = 20;
const int32_t CLONE_PIN_AUTH_TIMEOUT = 10;
const int32_t HML_SESSION_TIMEOUT = 10;
const int32_t SESSION_HEARTBEAT_TIMEOUT = 50;
const int32_t PIN_AUTH_TIMEOUT = 60;
const int32_t EVENT_TIMEOUT = 5000;

constexpr uint16_t OPEN_PROCESS_NAME_WHITE_LIST_NUM = 1;
constexpr uint16_t CLOSE_PROCESS_NAME_WHITE_LIST_NUM = 4;
constexpr const static char* OPEN_PROCESS_NAME_WHITE_LIST[OPEN_PROCESS_NAME_WHITE_LIST_NUM] = {
    "com.example.myapplication"
};
constexpr const static char* CLOSE_PROCESS_NAME_WHITE_LIST[CLOSE_PROCESS_NAME_WHITE_LIST_NUM] = {
    "CollaborationFwk",
    "gameservice_server",
    "wear_link_service",
    "watch_system_service"
};

constexpr const static char* PROCESS_NAME_PROXY_ADAPTATION_LIST[] = {
    "gameservice_server"
};
constexpr uint32_t PROCESS_NAME_PROXY_ADAPTATION_LIST_NUM = std::size(PROCESS_NAME_PROXY_ADAPTATION_LIST);

int32_t AuthManagerBase::AuthenticateDevice(const std::string &pkgName, int32_t authType,
    const std::string &deviceId, const std::string &extra)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

int32_t AuthManagerBase::UnAuthenticateDevice(const std::string &pkgName,
    const std::string &udid, int32_t bindLevel)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

int32_t AuthManagerBase::UnBindDevice(const std::string &pkgName, const std::string &udid,
    int32_t bindLevel, const std::string &extra)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

void AuthManagerBase::OnSessionOpened(int32_t sessionId, int32_t sessionSide, int32_t result)
{
    LOGE("is not implemented in the current version");
}

void AuthManagerBase::OnSessionClosed(const int32_t sessionId)
{
    LOGE("is not implemented in the current version");
}

void AuthManagerBase::OnSessionDisable()
{
    LOGE("is not implemented in the current version");
}

void AuthManagerBase::OnDataReceived(const int32_t sessionId, const std::string message)
{
    LOGE("is not implemented in the current version");
}

void AuthManagerBase::OnSoftbusJoinLNNResult(const int32_t sessionId,
    const char *networkId, int32_t result)
{
    LOGE("is not implemented in the current version");
}

void AuthManagerBase::OnGroupCreated(int64_t requestId, const std::string &groupId)
{
    LOGE("is not implemented in the current version");
}

void AuthManagerBase::OnMemberJoin(int64_t requestId, int32_t status, int32_t operationCode)
{
    LOGE("is not implemented in the current version");
}

int32_t AuthManagerBase::EstablishAuthChannel(const std::string &deviceId)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

void AuthManagerBase::StartNegotiate(const int32_t &sessionId)
{
    LOGE("is not implemented in the current version");
}

void AuthManagerBase::RespNegotiate(const int32_t &sessionId)
{
    LOGE("is not implemented in the current version");
}

void AuthManagerBase::SendAuthRequest(const int32_t &sessionId)
{
    LOGE("is not implemented in the current version");
}

int32_t AuthManagerBase::StartAuthProcess(const int32_t &action)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

void AuthManagerBase::StartRespAuthProcess()
{
    LOGE("is not implemented in the current version");
}

int32_t AuthManagerBase::CreateGroup()
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

int32_t AuthManagerBase::ProcessPincode(const std::string &pinCode)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

std::string AuthManagerBase::GetConnectAddr(std::string deviceId)
{
    LOGE("is not implemented in the current version");
    return "";
}

int32_t AuthManagerBase::JoinNetwork()
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

void AuthManagerBase::AuthenticateFinish()
{
    LOGE("is not implemented in the current version");
}

bool AuthManagerBase::GetIsCryptoSupport()
{
    LOGE("is not implemented in the current version");
    return false;
}

int32_t AuthManagerBase::SetAuthRequestState(
    std::shared_ptr<AuthRequestState> authRequestState)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

int32_t AuthManagerBase::SetAuthResponseState(
    std::shared_ptr<AuthResponseState> authResponseState)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

int32_t AuthManagerBase::GetPinCode(std::string &code)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

std::string AuthManagerBase::GenerateGroupName()
{
    LOGE("is not implemented in the current version");
    return "";
}

void AuthManagerBase::HandleAuthenticateTimeout(std::string name)
{
    LOGE("is not implemented in the current version");
}

std::string AuthManagerBase::GeneratePincode()
{
    LOGE("is not implemented in the current version");
    return "";
}

void AuthManagerBase::ShowConfigDialog()
{
    LOGE("is not implemented in the current version");
}

void AuthManagerBase::ShowAuthInfoDialog(bool authDeviceError)
{
    LOGE("is not implemented in the current version");
}

void AuthManagerBase::ShowStartAuthDialog()
{
    LOGE("is not implemented in the current version");
}

int32_t AuthManagerBase::OnUserOperation(int32_t action, const std::string &params)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

int32_t AuthManagerBase::SetPageId(int32_t pageId)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

int32_t AuthManagerBase::SetReasonAndFinish(int32_t reason, int32_t state)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

bool AuthManagerBase::IsIdenticalAccount()
{
    LOGE("is not implemented in the current version");
    return false;
}

int32_t AuthManagerBase::RegisterUiStateCallback(const std::string pkgName)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

int32_t AuthManagerBase::UnRegisterUiStateCallback(const std::string pkgName)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

int32_t AuthManagerBase::ImportAuthCode(const std::string &pkgName,
    const std::string &authCode)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

int32_t AuthManagerBase::BindTarget(const std::string &pkgName, const PeerTargetId &targetId,
    const std::map<std::string, std::string> &bindParam, int sessionId, uint64_t logicalSessionId)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

int32_t AuthManagerBase::RegisterAuthenticationType(int32_t authenticationType)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

int32_t AuthManagerBase::StopAuthenticateDevice(const std::string &pkgName)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

int32_t AuthManagerBase::DeleteGroup(const std::string &pkgName, const std::string &deviceId)
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

int32_t AuthManagerBase::GetReason()
{
    LOGE("is not implemented in the current version");
    return ERR_DM_FAILED;
}

void AuthManagerBase::GetBindTargetParams(std::string &pkgName, PeerTargetId &targetId,
    std::map<std::string, std::string> &bindParam)
{
    LOGE("is not implemented in the current version");
    return;
}

void AuthManagerBase::GetAuthCodeAndPkgName(std::string &pkgName, std::string &authCode)
{
    LOGE("is not implemented in the current version");
    return;
}

void AuthManagerBase::SetBindTargetParams(const PeerTargetId &targetId)
{
    LOGE("is not implemented in the current version");
    return;
}

void AuthManagerBase::RegisterCleanNotifyCallback(CleanNotifyCallback cleanNotifyCallback)
{
    LOGE("is not implemented in the current version");
    return;
}

void AuthManagerBase::RegisterStopTimerAndDelDpCallback(
    StopTimerAndDelDpCallback stopTimerAndDelDpCallback)
{
    LOGE("is not implemented in the current version");
}

std::string AuthManagerBase::ConvertSrcVersion(const std::string &version,
    const std::string &edition)
{
    std::string srcVersion;
    if (!version.empty()) {
        srcVersion = version;
    } else if (!edition.empty()) {
        srcVersion = edition;
    } else {
        srcVersion = DM_VERSION_5_1_0;
    }
    LOGI("version %{public}s, edition %{public}s, srcVersion is %{public}s.",
        version.c_str(), edition.c_str(), srcVersion.c_str());
    return srcVersion;
}

// Scenario 1: remote side specifies userId -> verify it is a foreground user
// Scenario 2: remote side does not specify userId
//   2.1: single user -> use the unique foreground user
//   2.2: multiple users -> use the current main screen user
int32_t AuthManagerBase::DmGetUserId(int32_t displayId)
{
    std::vector<int32_t> userIds;
    int32_t ret = MultipleUserConnector::GetForegroundUserIds(userIds);
    if (ret != DM_OK) {
        LOGE("RespQueryTokenId: GetForegroundUserIds failed, ret: %{public}d", ret);
        return -1;
    }
    if (userIds.empty()) {
        LOGE("RespQueryTokenId: GetForegroundUserIds no foreground users");
        return -1;
    }
    if (displayId != -1) {
        return ResolveUserIdByDisplayId(displayId, userIds);
    }
    if (userIds.size() == 1) {
        return userIds[0];
    }
    return GetMainScreenUserId();
}

int32_t AuthManagerBase::ResolveUserIdByDisplayId(int32_t displayId,
    const std::vector<int32_t> &foregroundUserIds)
{
    int32_t userId = -1;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(
        displayId, userId);
    if (ret != DM_OK) {
        LOGE("RespQueryTokenId: fail to get userId by displayId %{public}d", displayId);
        return -1;
    }
    for (const auto &fgUserId : foregroundUserIds) {
        if (userId == fgUserId) {
            return userId;
        }
    }
    LOGE("RespQueryTokenId: userId %{public}d is not a foreground user", userId);
    return -1;
}

int32_t AuthManagerBase::GetMainScreenUserId()
{
    int32_t userId = -1;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != DM_OK) {
        LOGE("get foreground user failed in multi users with error %{public}d", ret);
        return -1;
    }
    return userId;
}

bool AuthManagerBase::IsTransferReady()
{
    return isTransferReady_;
}

void AuthManagerBase::SetTransferReady(bool version)
{
    isTransferReady_ = version;
}

void AuthManagerBase::ClearSoftbusSessionCallback()
{}

void AuthManagerBase::PrepareSoftbusSessionCallback()
{}

void AuthManagerBase::EnableInsensibleSwitching()
{
    insensibleSwitching = true;
}

void AuthManagerBase::DisableInsensibleSwitching()
{
    insensibleSwitching = false;
}

bool AuthManagerBase::NeedInsensibleSwitching()
{
    return insensibleSwitching;
}

int32_t AuthManagerBase::ParseAuthType(
    const std::map<std::string, std::string> &bindParam, int32_t &authType)
{
    auto iter = bindParam.find(PARAM_KEY_AUTH_TYPE);
    if (iter == bindParam.end()) {
        LOGE("bind param key: %{public}s not exist.", PARAM_KEY_AUTH_TYPE);
        return ERR_DM_INPUT_PARA_INVALID;
    }
    const std::string &authTypeStr = iter->second;
    if (authTypeStr.empty()) {
        LOGE("bind param %{public}s is empty.", PARAM_KEY_AUTH_TYPE);
        return ERR_DM_INPUT_PARA_INVALID;
    }
    if (authTypeStr.length() > 1) {
        LOGE("bind param %{public}s length is unsupported.", PARAM_KEY_AUTH_TYPE);
        return ERR_DM_INPUT_PARA_INVALID;
    }
    char firstChar = authTypeStr[0];
    if (!isdigit(static_cast<unsigned char>(firstChar))) {
        LOGE("bind param %{public}s format is unsupported.", PARAM_KEY_AUTH_TYPE);
        return ERR_DM_INPUT_PARA_INVALID;
    }
    authType = atoi(authTypeStr.c_str());
    if (authType < DM_AUTH_TYPE_MIN || authType > DM_AUTH_TYPE_MAX) {
        LOGE("bind param %{public}s value is out of range.", PARAM_KEY_AUTH_TYPE);
        return ERR_DM_INPUT_PARA_INVALID;
    }
    return DM_OK;
}

void AuthManagerBase::OnAuthDeviceDataReceived(int32_t sessionId, std::string message)
{
    LOGE("OnAuthDeviceDataReceived is not used in the new protocol");
}

int32_t AuthManagerBase::EndDream()
{
    auto &powerMgrClient = OHOS::PowerMgr::PowerMgrClient::GetInstance();
    if (!powerMgrClient.IsScreenOn()) {
        LOGW("screen not on");
        return ERR_DM_FAILED;
    }
#if defined(SUPPORT_SCREENLOCK)
    CHECK_NULL_RETURN(OHOS::ScreenLock::ScreenLockManager::GetInstance(), ERR_DM_FAILED);
    if (!OHOS::ScreenLock::ScreenLockManager::GetInstance()->IsScreenLocked()) {
        LOGI("screen not locked");
        return DM_OK;
    }
#endif
    PowerMgr::PowerErrors ret = powerMgrClient.WakeupDevice(
        PowerMgr::WakeupDeviceType::WAKEUP_DEVICE_END_DREAM, "end_dream");
    if (ret != OHOS::PowerMgr::PowerErrors::ERR_OK) {
        LOGE("fail to end dream, err:%{public}d", ret);
        return ERR_DM_FAILED;
    }
    LOGI("end dream success");
    return DM_OK;
}

bool AuthManagerBase::CheckProcessNameInWhiteList(const std::string &processName)
{
    LOGI("start");
#ifdef DEVICE_MANAGER_COMMON_FLAG
    return IsProcessNameInList(processName, OPEN_PROCESS_NAME_WHITE_LIST,
        OPEN_PROCESS_NAME_WHITE_LIST_NUM);
#else
    return IsProcessNameInList(processName, CLOSE_PROCESS_NAME_WHITE_LIST,
        CLOSE_PROCESS_NAME_WHITE_LIST_NUM);
#endif
}

bool AuthManagerBase::CheckProcessNameInProxyAdaptationList(const std::string &processName)
{
    LOGI("start");
    return IsProcessNameInList(processName, PROCESS_NAME_PROXY_ADAPTATION_LIST,
        PROCESS_NAME_PROXY_ADAPTATION_LIST_NUM);
}

bool AuthManagerBase::IsProcessNameInList(const std::string &processName,
    const char * const list[], uint32_t listSize)
{
    if (processName.empty()) {
        LOGE("processName is empty");
        return false;
    }
    for (uint32_t index = 0; index < listSize; ++index) {
        std::string whitePkgName(list[index]);
        if (processName == whitePkgName) {
            LOGI("processName = %{public}s in list.", processName.c_str());
            return true;
        }
    }
    LOGI("processName = %{public}s not in list.", processName.c_str());
    return false;
}

void AuthManagerBase::DeleteTimer()
{}

void AuthManagerBase::OnLeaveLNNResult(const std::string &pkgName,
    const std::string &networkId, int32_t retCode)
{}

void AuthManagerBase::NotifyRemoteFailed(int32_t sessionId, int32_t reason,
    uint64_t logicalSessionId)
{
    (void)sessionId;
    (void)reason;
    (void)logicalSessionId;
}
}  // namespace DistributedHardware
}  // namespace OHOS
