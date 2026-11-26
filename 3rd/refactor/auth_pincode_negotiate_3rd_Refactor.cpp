/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with License.
 * You may obtain a copy of License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See License for the specific language governing permissions and
 * limitations under License.
 */

#include <cstdlib>
#include <map>
#include <memory>
#include <securec.h>

#include "accesstoken_kit.h"
#include "business_event.h"
#include "device_auth.h"
#include "hap_token_info.h"
#include "os_account_manager.h"
#include "parameter.h"

#include "auth_pincode_manager_3rd.h"
#include "app_manager_3rd.h"
#include "dm_auth_pincode_message_processor_3rd.h"
#include "dm_crypto_3rd.h"
#include "dm_log_3rd.h"
#include "dm_timer_3rd.h"
#include "dm_constants_3rd.h"
#include "dm_anonymous_3rd.h"
#include "dm_auth_pincode_context_3rd.h"
#include "dm_auth_pincode_state_3rd_Refactor.h"
#include "json_object.h"
#include "multiple_user_connector_3rd.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace DistributedHardware {

DmAuthPincodeStateTypeRefactor AuthPincodeSrcStartStateRefactor::GetStateType()
{
    return DmAuthPincodeStateTypeRefactor::ACL_AUTH_PINCODE_SRC_START_STATE;
}

int32_t AuthPincodeSrcStartStateRefactor::Action(std::shared_ptr<DmAuthPincodeContext> context)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    return DM_OK;
}

DmAuthPincodeStateTypeRefactor AuthPincodeSrcPinNegotiateStartStateRefactor::GetStateType()
{
    return DmAuthPincodeStateTypeRefactor::ACL_AUTH_PINCODE_SRC_NEGOTIATE_STATE;
}

int32_t AuthPincodeSrcPinNegotiateStartStateRefactor::Action(std::shared_ptr<DmAuthPincodeContext> context)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->authPinMsgProc3rd, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->softbusConnector, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->softbusConnector->GetSoftbusSession(), ERR_DM_POINT_NULL);
    LOGI("AuthPincodeSrcPinNegotiateStartStateRefactor::Action sessionId %{public}d.", context->sessionId);
    context->reply = ERR_DM_AUTH_REJECT;
    context->accesser.deviceIdHash = Crypto3rd::GetUdidHash(context->accesser.deviceId);
    context->accesser.accountIdHash = Crypto3rd::GetAccountIdHash16(context->accesser.accountId);
    context->accesser.tokenIdHash = Crypto3rd::GetTokenIdHash(std::to_string(context->accesser.tokenId));

    std::string message = context->authPinMsgProc3rd->CreateMessage(DmPincodeMessageType::AUTH_PINCODE_REQ_NEGOTIATE,
        context);
    int32_t ret = context->softbusConnector->GetSoftbusSession()->SendData(context->sessionId, message);
    if (ret != DM_OK) {
        LOGE("AuthPincodeSrcPinNegotiateStartStateRefactor send negotiate message failed, ret: %{public}d", ret);
        context->reason = ret;
        return ret;
    }
    if (context->timer != nullptr) {
        context->timer->StartTimer(std::string(NEGOTIATE_TIMEOUT_TASK),
            DmAuthPincodeState3rdRefactor::GetTaskTimeout(context, NEGOTIATE_TIMEOUT_TASK, NEGOTIATE_TIMEOUT),
            [this, context] (std::string name) {
                DmAuthPincodeState3rdRefactor::HandleAuthenticateTimeout(context, name);
            });
    }
    return DM_OK;
}

DmAuthPincodeStateTypeRefactor AuthPincodeSinkPinNegotiateStartStateRefactor::GetStateType()
{
    return DmAuthPincodeStateTypeRefactor::ACL_AUTH_PINCODE_SINK_NEGOTIATE_STATE;
}

int32_t AuthPincodeSinkPinNegotiateStartStateRefactor::Action(std::shared_ptr<DmAuthPincodeContext> context)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->timer, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->authPinMsgProc3rd, ERR_DM_POINT_NULL);
    LOGI("AuthPincodeSinkPinNegotiateStartStateRefactor::Action sessionid %{public}d", context->sessionId);
    context->timer->StartTimer(std::string(AUTHENTICATE_TIMEOUT_TASK),
        AUTHENTICATE_TIMEOUT,
        [this, context] (std::string name) {
            DmAuthPincodeState3rdRefactor::HandleAuthenticateTimeout(context, name);
    });
    int32_t ret = RespQueryAcceseeIds(context);
    if (ret != DM_OK) {
        LOGE("AuthPincodeSinkPinNegotiateStartStateRefactor::Action proc response negotiate failed");
        context->timer->DeleteTimer(std::string(AUTHENTICATE_TIMEOUT_TASK));
        context->reason = ret;
        return ret;
    }
    context->authPinMsgProc3rd->CreateAndSendMsg(DmPincodeMessageType::AUTH_PINCODE_RESP_NEGOTIATE, context);
    context->timer->StartTimer(std::string(WAIT_REQUEST_TIMEOUT_TASK),
        DmAuthPincodeState3rdRefactor::GetTaskTimeout(context, WAIT_REQUEST_TIMEOUT_TASK, WAIT_REQUEST_TIMEOUT),
        [this, context] (std::string name) {
            DmAuthPincodeState3rdRefactor::HandleAuthenticateTimeout(context, name);
        });
    return DM_OK;
}

int32_t AuthPincodeSinkPinNegotiateStartStateRefactor::RespQueryAcceseeIds(
    std::shared_ptr<DmAuthPincodeContext> context)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    char localDeviceId[DEVICE_UUID_LENGTH] = {0};
    if (GetDevUdid(localDeviceId, DEVICE_UUID_LENGTH) != 0) {
        LOGE("RespQueryAcceseeIds get local udid failed.");
        return ERR_DM_FAILED;
    }
    context->accessee.deviceId = std::string(localDeviceId);
    (void)memset_s(localDeviceId, DEVICE_UUID_LENGTH, 0, DEVICE_UUID_LENGTH);
    context->accessee.deviceIdHash = Crypto3rd::GetUdidHash(context->accessee.deviceId);
    context->accessee.userId = MultipleUserConnector3rd::GetFirstForegroundUserId();
    if (context->accessee.userId < 0) {
        LOGE("get accessee userId: %{public}d failed.", context->accessee.userId);
        return ERR_DM_GET_LOCAL_USERID_FAILED;
    }
    context->accessee.accountId = MultipleUserConnector3rd::GetOhosAccountIdByUserId(context->accessee.userId);
    context->accessee.accountIdHash = Crypto3rd::GetAccountIdHash16(context->accessee.accountId);
    if (AppManager3rd::GetInstance().GetNativeTokenIdByName(context->accessee.processName,
        context->accessee.tokenId) == DM_OK) {
        context->accessee.bindLevel = DmRole::DM_ROLE_SA;
    } else if (AppManager3rd::GetInstance().GetHapTokenIdByName(context->accessee.userId,
        context->accessee.processName, 0, context->accessee.tokenId) == DM_OK) {
        context->accessee.bindLevel = DmRole::DM_ROLE_FA;
    } else {
        LOGE("sink not contain the bundlename %{public}s.", context->accessee.processName.c_str());
        return ERR_DM_GET_TOKENID_FAILED;
    }
    context->accessee.tokenIdHash = Crypto3rd::GetTokenIdHash(std::to_string(context->accessee.tokenId));
    context->processInfo.tokenId = context->accessee.tokenId;
    context->processInfo.uid = context->accessee.uid;
    context->processInfo.userId = context->accessee.userId;
    context->processInfo.processName = context->accessee.processName;
    context->processInfo.businessName = context->accessee.businessName;
    return DM_OK;
}
} // namespace DistributedHardware
} // namespace OHOS
