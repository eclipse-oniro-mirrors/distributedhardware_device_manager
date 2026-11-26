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

#include "auth_pincode_manager_3rd.h"
#include "dm_anonymous_3rd.h"
#include "dm_auth_pincode_context_3rd.h"
#include "dm_auth_pincode_message_processor_3rd.h"
#include "dm_auth_pincode_state_3rd_Refactor.h"
#include "dm_auth_pincode_state_machine_3rd.h"
#include "dm_crypto_3rd.h"
#include "dm_log_3rd.h"
#include "hichain_auth_connector_3rd.h"
#include "multiple_user_connector_3rd.h"

namespace OHOS {
namespace DistributedHardware {

DmAuthPincodeStateTypeRefactor AuthPincodeSrcPinAuthStartStateRefactor::GetStateType()
{
    return DmAuthPincodeStateTypeRefactor::ACL_AUTH_PINCODE_SRC_PIN_AUTH_START_STATE;
}

int32_t AuthPincodeSrcPinAuthStartStateRefactor::Action(std::shared_ptr<DmAuthPincodeContext> context)
{
    LOGI("AuthPincodeSrcPinAuthStartStateRefactor::Action start");
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->hiChainAuthConnector, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->authPinStateMac3rd, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->authPinMsgProc3rd, ERR_DM_POINT_NULL);
    auto ret = context->hiChainAuthConnector->AuthCredentialPinCode(context->accesser.userId, context->requestId,
        context->importAuthCode);
    if (ret != DM_OK) {
        LOGE("AuthPincodeSrcPinAuthStartStateRefactor::Action call AuthCredentialPinCode failed.");
        return ret;
    }
    // wait for onTransmit from hiChain
    auto retEvent = context->authPinStateMac3rd->WaitExpectEvent(DmEventType::ON_TRANSMIT);
    if (retEvent == DmEventType::ON_TRANSMIT) {
        // send 1030 msg
        context->authPinMsgProc3rd->CreateAndSendMsg(DmPincodeMessageType::AUTH_PINCODE_REQ_PIN_AUTH_START, context);
        return DM_OK;
    } else if (retEvent == DmEventType::ON_ERROR) {
        LOGI("AuthPincodeSrcPinAuthStartStateRefactor::Action ON_ERROR failed, maybe retry.");
        return DM_OK;
    }

    return STOP_BIND;
}

DmAuthPincodeStateTypeRefactor AuthPincodeSinkPinAuthStartStateRefactor::GetStateType()
{
    return DmAuthPincodeStateTypeRefactor::ACL_AUTH_PINCODE_SINK_PIN_AUTH_START_STATE;
}

int32_t AuthPincodeSinkPinAuthStartStateRefactor::Action(std::shared_ptr<DmAuthPincodeContext> context)
{
    LOGI("AuthPincodeSinkPinAuthStartStateRefactor::Action start");
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->timer, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->hiChainAuthConnector, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->authPinStateMac3rd, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->authPinMsgProc3rd, ERR_DM_POINT_NULL);
    context->timer->DeleteTimer(std::string(WAIT_REQUEST_TIMEOUT_TASK));

    context->timer->StartTimer(std::string(WAIT_PIN_AUTH_TIMEOUT_TASK),
        DmAuthPincodeState3rdRefactor::GetTaskTimeout(context, WAIT_PIN_AUTH_TIMEOUT_TASK, PIN_AUTH_TIMEOUT),
        [context] (std::string name) {
            DmAuthPincodeState3rdRefactor::HandleAuthenticateTimeout(context, name);
        });

    std::string pinCodeHash = GetAnonyString(Crypto3rd::Sha256(context->importAuthCode));
    LOGI("AuthPincodeSinkPinAuthStartStateRefactor pinCodeHash: %{public}s", GetAnonyString(pinCodeHash).c_str());
    // process pincode auth
    auto ret = context->hiChainAuthConnector->ProcessCredData(context->requestId, context->transmitData);
    if (ret != DM_OK) {
        LOGE("AuthPincodeSinkPinAuthStartStateRefactor::Action call ProcessCredData err.");
        return ret;
    }
    // wait for onTransmit from hiChain
    auto retEvent = context->authPinStateMac3rd->WaitExpectEvent(DmEventType::ON_TRANSMIT);
    if (retEvent == DmEventType::ON_TRANSMIT) {
        // send 1040 msg
        context->authPinMsgProc3rd->CreateAndSendMsg(DmPincodeMessageType::AUTH_PINCODE_RESP_PIN_AUTH_START, context);
        return DM_OK;
    }
    if (retEvent == DmEventType::ON_ERROR) {
        LOGI("AuthPincodeSinkPinAuthStartStateRefactor::Action ON_ERROR failed, maybe retry.");
        return DM_OK;
    }
    return STOP_BIND;
}

DmAuthPincodeStateTypeRefactor AuthPincodeSrcPinAuthMsgNegotiateStateRefactor::GetStateType()
{
    return DmAuthPincodeStateTypeRefactor::ACL_AUTH_PINCODE_SRC_PIN_AUTH_MSG_NEGOTIATE_STATE;
}

int32_t AuthPincodeSrcPinAuthMsgNegotiateStateRefactor::Action(std::shared_ptr<DmAuthPincodeContext> context)
{
    LOGI("AuthPincodeSrcPinAuthMsgNegotiateStateRefactor::Action start");
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->hiChainAuthConnector, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->authPinStateMac3rd, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->authPinMsgProc3rd, ERR_DM_POINT_NULL);
    auto ret = context->hiChainAuthConnector->ProcessCredData(context->requestId, context->transmitData);
    if (ret != DM_OK) {
        LOGE("AuthPincodeSrcPinAuthMsgNegotiateStateRefactor::Action call ProcessCredData err.");
        return ret;
    }
    // wait for onTransmit from hiChain
    auto retEvent = context->authPinStateMac3rd->WaitExpectEvent(DmEventType::ON_TRANSMIT);
    if (retEvent == DmEventType::ON_TRANSMIT) {
        // send 1031 msg
        context->authPinMsgProc3rd->CreateAndSendMsg(DmPincodeMessageType::AUTH_PINCODE_REQ_PIN_AUTH_MSG_NEGOTIATE,
            context);
        return DM_OK;
    }
    if (retEvent == DmEventType::ON_ERROR) {
        LOGI("AuthPincodeSrcPinAuthMsgNegotiateStateRefactor::AuthDevice ON_ERROR failed, maybe retry.");
        return DM_OK;
    }
    LOGE("AuthPincodeSrcPinAuthMsgNegotiateStateRefactor::Action failed.");
    return STOP_BIND;
}

DmAuthPincodeStateTypeRefactor AuthPincodeSinkPinAuthMsgNegotiateStateRefactor::GetStateType()
{
    return DmAuthPincodeStateTypeRefactor::ACL_AUTH_PINCODE_SINK_PIN_AUTH_MSG_NEGOTIATE_STATE;
}

int32_t AuthPincodeSinkPinAuthMsgNegotiateStateRefactor::Action(std::shared_ptr<DmAuthPincodeContext> context)
{
    LOGI("AuthPincodeSinkPinAuthMsgNegotiateStateRefactor::Action start");
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->timer, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->hiChainAuthConnector, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->authPinStateMac3rd, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->authPinMsgProc3rd, ERR_DM_POINT_NULL);
    auto ret = context->hiChainAuthConnector->ProcessCredData(context->requestId, context->transmitData);
    if (ret != DM_OK) {
        LOGE("AuthPincodeSinkPinAuthMsgNegotiateStateRefactor::Action call ProcessCredData err.");
        return ret;
    }
    // wait for onTransmit from hiChain
    auto retEvent = context->authPinStateMac3rd->WaitExpectEvent(DmEventType::ON_TRANSMIT);
    if (retEvent == DmEventType::ON_TRANSMIT) {
        // send 1041 msg
        context->authPinMsgProc3rd->CreateAndSendMsg(DmPincodeMessageType::AUTH_PINCODE_RESP_PIN_AUTH_MSG_NEGOTIATE,
            context);
    } else if (retEvent == DmEventType::ON_ERROR) {
        LOGI("AuthPincodeSinkPinAuthMsgNegotiateStateRefactor::Action WAIT ON_TRANSMIT ON_ERROR failed, maybe retry.");
        return DM_OK;
    } else {
        return STOP_BIND;
    }

    retEvent = context->authPinStateMac3rd->WaitExpectEvent(DmEventType::ON_SESSION_KEY_RETURNED);
    if (retEvent == DmEventType::ON_SESSION_KEY_RETURNED) {
        retEvent = context->authPinStateMac3rd->WaitExpectEvent(DmEventType::ON_FINISH);
        if (retEvent == DmEventType::ON_FINISH || retEvent == DmEventType::ON_ERROR) {
            context->timer->DeleteTimer(std::string(WAIT_PIN_AUTH_TIMEOUT_TASK));
            return DM_OK;
        }
    }  else if (retEvent == DmEventType::ON_ERROR) {
        LOGI("WAIT ON_SESSION_KEY_RETURNED ON_ERROR failed, maybe retry.");
        return DM_OK;
    }
    LOGE("AuthPincodeSinkPinAuthMsgNegotiateStateRefactor::Action failed.");
    return STOP_BIND;
}

DmAuthPincodeStateTypeRefactor AuthPincodeSrcPinAuthDoneStateRefactor::GetStateType()
{
    return DmAuthPincodeStateTypeRefactor::ACL_AUTH_PINCODE_SRC_PIN_AUTH_DONE_STATE;
}

int32_t AuthPincodeSrcPinAuthDoneStateRefactor::Action(std::shared_ptr<DmAuthPincodeContext> context)
{
    LOGI("AuthPincodeSrcPinAuthDoneStateRefactor::Action start");
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->hiChainAuthConnector, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->authPinStateMac3rd, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->authPinMsgProc3rd, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(context->timer, ERR_DM_POINT_NULL);
    std::string onTransmitData = context->transmitData;
    if (context->hiChainAuthConnector->ProcessCredData(context->requestId, onTransmitData) != DM_OK) {
        LOGE("AuthPincodeSrcPinAuthDoneStateRefactor::Action failed, processCredData failed.");
        return ERR_DM_FAILED;
    }

    // wait for ON_SESSION_KEY_RETURNED from hichain
    DmEventType ret = context->authPinStateMac3rd->WaitExpectEvent(ON_SESSION_KEY_RETURNED);
    if (ret != ON_SESSION_KEY_RETURNED) {
        LOGE("Action failed, ON_SESSION_KEY_RETURNED event failed, other event arriverd.");
        return ERR_DM_FAILED;
    }

    // wait for ON_FINISH from hichain
    ret = context->authPinStateMac3rd->WaitExpectEvent(ON_FINISH);
    if (ret == ON_FINISH) {
        LOGI("AuthPincodeSrcPinAuthDoneStateRefactor::Action wait ON_FINISH done");
        context->timer->DeleteTimer(std::string(WAIT_PIN_AUTH_TIMEOUT_TASK));
        // send 1050
        context->authPinMsgProc3rd->CreateAndSendMsg(DmPincodeMessageType::AUTH_PINCODE_REQ_FINISH, context);
        return DM_OK;
    } else if (ret == ON_ERROR) {
        LOGE("AuthPincodeSrcPinAuthDoneStateRefactor::Action, ON_FINISH event not arriverd, maybe retry.");
        return DM_OK;
    }

    return ERR_DM_FAILED;
}
} // namespace DistributedHardware
} // namespace OHOS
