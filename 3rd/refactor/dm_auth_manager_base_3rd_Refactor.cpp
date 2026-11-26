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

#include "dm_auth_manager_base_3rd_Refactor.h"

#include "multiple_user_connector_3rd.h"

#include "dm_constants_3rd.h"
#include "dm_error_type_3rd.h"
#include "dm_log_3rd.h"

#ifdef OS_ACCOUNT_PART_EXISTS
#include "os_account_manager.h"
using namespace OHOS::AccountSA;
#endif // OS_ACCOUNT_PART_EXISTS

namespace OHOS {
namespace DistributedHardware {
const char* TAG_DM_VERSION = "dmVersion";
const char* TAG_DM_VERSION_V2 = "dmVersionV2";

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
const int32_t CLONE_WAIT_REQUEST_TIMEOUT = 30;
const int32_t CLONE_SESSION_HEARTBEAT_TIMEOUT = 20;
const int32_t CLONE_PIN_AUTH_TIMEOUT = 10;
const int32_t HML_SESSION_TIMEOUT = 10;
const int32_t SESSION_HEARTBEAT_TIMEOUT = 50;
const int32_t PIN_AUTH_TIMEOUT = 60;
const int32_t EVENT_TIMEOUT = 5000; // 5000 ms

int32_t AuthManagerBase3rdRefactor::AuthDevice3rd(const PeerTargetId3rd &targetId,
    const std::map<std::string, std::string> &authParam, int32_t sessionId, uint64_t logicalSessionId)
{
    LOGE("AuthDevice3rd is not implemented in the current version");
    (void)targetId;
    (void)authParam;
    (void)sessionId;
    (void)logicalSessionId;
    return ERR_DM_FAILED;
}

int32_t AuthManagerBase3rdRefactor::AuthPincode(const PeerTargetId3rd &targetId,
    const std::map<std::string, std::string> &authParam, int32_t sessionId, uint64_t logicalSessionId)
{
    LOGE("AuthPincode is not implemented in the current version");
    (void)targetId;
    (void)authParam;
    (void)sessionId;
    (void)logicalSessionId;
    return ERR_DM_FAILED;
}

int32_t AuthManagerBase3rdRefactor::AuthCredential(const PeerTargetId3rd &targetId,
    const std::map<std::string, std::string> &authParam, int32_t sessionId, uint64_t logicalSessionId)
{
    LOGE("AuthCredential is not implemented in the current version");
    (void)targetId;
    (void)authParam;
    (void)sessionId;
    (void)logicalSessionId;
    return ERR_DM_FAILED;
}

void AuthManagerBase3rdRefactor::OnSessionOpened(int32_t sessionId, int32_t sessionSide, int32_t result)
{
    LOGE("OnSessionOpened is not implemented in the current version");
}

void AuthManagerBase3rdRefactor::OnSessionClosed(const int32_t sessionId)
{
    LOGE("OnSessionClosed is not implemented in the current version");
}

void AuthManagerBase3rdRefactor::OnSessionDisable()
{
    LOGE("OnSessionDisable is not implemented in the current version");
}

void AuthManagerBase3rdRefactor::OnDataReceived(const int32_t sessionId, const std::string &message)
{
    LOGE("OnDataReceived is not implemented in the current version");
}

int32_t AuthManagerBase3rdRefactor::EstablishAuthChannel(const std::string &deviceId)
{
    LOGE("EstablishAuthChannel is not implemented in the current version");
    return ERR_DM_FAILED;
}

void AuthManagerBase3rdRefactor::StartNegotiate(const int32_t sessionId)
{
    LOGE("StartNegotiate is not implemented in the current version");
}

void AuthManagerBase3rdRefactor::RespNegotiate(const int32_t sessionId)
{
    LOGE("RespNegotiate is not implemented in the current version");
}

void AuthManagerBase3rdRefactor::SendAuthRequest(const int32_t sessionId)
{
    LOGE("SendAuthRequest is not implemented in the current version");
}

int32_t AuthManagerBase3rdRefactor::StartAuthProcess(const int32_t action)
{
    LOGE("StartAuthProcess is not implemented in the current version");
    return ERR_DM_FAILED;
}

void AuthManagerBase3rdRefactor::StartRespAuthProcess()
{
    LOGE("StartRespAuthProcess is not implemented in the current version");
}

int32_t AuthManagerBase3rdRefactor::GetPinCode(std::string &code)
{
    LOGE("GetPinCode is not implemented in the current version");
    return ERR_DM_FAILED;
}

void AuthManagerBase3rdRefactor::HandleAuthenticateTimeout(std::string name)
{
    LOGE("HandleAuthenticateTimeout is not implemented in the current version");
}

int32_t AuthManagerBase3rdRefactor::SetReasonAndFinish(int32_t reason, int32_t state)
{
    LOGE("SetReasonAndFinish is not implemented in the current version");
    return ERR_DM_FAILED;
}

int32_t AuthManagerBase3rdRefactor::ImportAuthCodeAndUid(const std::string &pkgName, const std::string &authCode,
    int32_t uid)
{
    LOGE("ImportAuthCode is not implemented in the current version");
    return ERR_DM_FAILED;
}

void AuthManagerBase3rdRefactor::RegisterCleanNotifyCallback(CleanNotifyCallback cleanNotifyCallback)
{
    LOGE("RegisterCleanNotifyCallback is not implemented in the current version");
    return;
}

void AuthManagerBase3rdRefactor::OnAuthDeviceDataReceived(int32_t sessionId, std::string message)
{
    LOGE("OnAuthDeviceDataReceived is not used in the new protocol");
}
}  // namespace DistributedHardware
}  // namespace OHOS
