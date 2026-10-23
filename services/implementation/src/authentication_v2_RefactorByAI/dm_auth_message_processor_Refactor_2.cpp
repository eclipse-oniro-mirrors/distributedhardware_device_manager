/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "dm_auth_message_processor_Refactor.h"

#include "access_control_profile.h"
#include "distributed_device_profile_client.h"
#include "service_info_unique_key.h"

#include "deviceprofile_connector.h"
#include "dm_log.h"
#include "dm_constants.h"
#include "dm_anonymous.h"
#include "dm_auth_manager_base.h"
#include "dm_auth_context.h"
#include "dm_auth_state_machine.h"
#include "dm_crypto.h"

namespace OHOS {
namespace DistributedHardware {

namespace {
void ParseSinkUserConfirmOpt(std::shared_ptr<DmAuthContext> &context, const JsonObject &jsonObject)
{
    if (context->direction != DmAuthDirection::DM_AUTH_SOURCE) {
        return;
    }
    LOGI("Source parse sink user confirm opt");
    int32_t userConfirmOpt = static_cast<int32_t>(USER_OPERATION_TYPE_CANCEL_AUTH);
    if (IsInt32(jsonObject, TAG_USER_CONFIRM_OPT)) {
        userConfirmOpt = jsonObject[TAG_USER_CONFIRM_OPT].Get<int32_t>();
    }
    if (userConfirmOpt == static_cast<int32_t>(USER_OPERATION_TYPE_ALLOW_AUTH) ||
        userConfirmOpt == static_cast<int32_t>(USER_OPERATION_TYPE_ALLOW_AUTH_ALWAYS)) {
        context->confirmOperation = static_cast<UiAction>(userConfirmOpt);
    }
}

bool CheckDeviceProxyItemFields(const JsonItemObject &item)
{
    return IsInt64(item, TAG_TOKEN_ID) && IsString(item, TAG_TRANSMIT_SK_ID) &&
        IsInt32(item, TAG_BIND_LEVEL) && IsInt64(item, TAG_TRANSMIT_SK_TIMESTAMP) &&
        IsString(item, TAG_TRANSMIT_CREDENTIAL_ID);
}

bool CheckServiceProxyItemFields(const JsonItemObject &item)
{
    return CheckDeviceProxyItemFields(item) && IsString(item, TAG_SRC_SUBJECT_PKGNAME) &&
        IsInt64(item, TAG_SUBJECT_SERVICEID);
}

bool CheckServiceInfoNumItem(const JsonItemObject &item)
{
    return IsInt32(item, SERVICEINFO_USER_ID) && IsInt64(item, SERVICEINFO_DISPLAY_ID) &&
        IsInt64(item, SERVICEINFO_SERVICE_ID) && item[SERVICEINFO_PUBLISH_STATE].IsNumberInteger() &&
        IsInt64(item, SERVICEINFO_SERVICE_OWNER_TOKEN_ID) &&
        IsInt64(item, SERVICEINFO_SERVICE_REGISTER_TOKEN_ID) && IsInt32(item, SERVICEINFO_DATA_LEN) &&
        IsInt64(item, SERVICEINFO_TIME_STAMP);
}

bool CheckServiceInfoStrItem(const JsonItemObject &item)
{
    return IsString(item, SERVICEINFO_DEVICE_ID) && IsString(item, SERVICEINFO_SERVICE_OWNER_PKG_NAME) &&
        IsString(item, SERVICEINFO_SERVICE_TYPE) && IsString(item, SERVICEINFO_SERVICE_NAME) &&
        IsString(item, SERVICEINFO_SERVICE_DISPLAY_NAME) && IsString(item, SERVICEINFO_SERVICE_CODE) &&
        IsString(item, SERVICEINFO_CUSTOM_DATA) && IsString(item, SERVICEINFO_VERSION) &&
        IsString(item, SERVICEINFO_EXTRA_DATA) && IsString(item, SERVICEINFO_DESCRIPTION);
}

bool CheckServiceInfoItem(const JsonItemObject &item)
{
    return CheckServiceInfoNumItem(item) && CheckServiceInfoStrItem(item);
}

void FillServiceInfoFromItem(const JsonItemObject &item, DistributedDeviceProfile::ServiceInfo &info)
{
    info.SetUserId(item[SERVICEINFO_USER_ID].Get<int32_t>());
    info.SetDisplayId(item[SERVICEINFO_DISPLAY_ID].Get<int64_t>());
    info.SetServiceId(item[SERVICEINFO_SERVICE_ID].Get<int64_t>());
    info.SetPublishState(item[SERVICEINFO_PUBLISH_STATE].Get<uint8_t>());
    info.SetUdid(item[SERVICEINFO_DEVICE_ID].Get<std::string>());
    info.SetServiceOwnerTokenId(item[SERVICEINFO_SERVICE_OWNER_TOKEN_ID].Get<int64_t>());
    info.SetServiceOwnerPkgName(item[SERVICEINFO_SERVICE_OWNER_PKG_NAME].Get<std::string>());
    info.SetServiceRegisterTokenId(item[SERVICEINFO_SERVICE_REGISTER_TOKEN_ID].Get<int64_t>());
    info.SetServiceType(item[SERVICEINFO_SERVICE_TYPE].Get<std::string>());
    info.SetServiceName(item[SERVICEINFO_SERVICE_NAME].Get<std::string>());
    info.SetServiceDisplayName(item[SERVICEINFO_SERVICE_DISPLAY_NAME].Get<std::string>());
    info.SetServiceCode(item[SERVICEINFO_SERVICE_CODE].Get<std::string>());
    info.SetCustomData(item[SERVICEINFO_CUSTOM_DATA].Get<std::string>());
    info.SetDataLen(item[SERVICEINFO_DATA_LEN].Get<int32_t>());
    info.SetTimeStamp(item[SERVICEINFO_TIME_STAMP].Get<int64_t>());
    info.SetVersion(item[SERVICEINFO_VERSION].Get<std::string>());
    info.SetExtraData(item[SERVICEINFO_EXTRA_DATA].Get<std::string>());
    info.SetDescription(item[SERVICEINFO_DESCRIPTION].Get<std::string>());
}
} // namespace

int32_t DmAuthMessageProcessor::ParseMessage(std::shared_ptr<DmAuthContext> context, const std::string &message)
{
    JsonObject jsonObject(message);
    if (context == nullptr || !IsMessageValid(jsonObject)) {
        return ERR_DM_FAILED;
    }
    DmMessageType msgType = static_cast<DmMessageType>(jsonObject[TAG_MSG_TYPE].Get<int32_t>());
    context->msgType = msgType;
    LOGI("message type %{public}d", context->msgType);
    if (CheckLogicalSessionId(jsonObject, context) != DM_OK) {
        LOGE("CheckLogicalSessionId failed.");
        return ERR_DM_FAILED;
    }
    auto itr = paraseMessageFuncMap_.find(msgType);
    if (itr == paraseMessageFuncMap_.end()) {
        LOGI("message type error %{public}d", context->msgType);
        return ERR_DM_FAILED;
    }
    return (this->*(itr->second))(jsonObject, context);
}

void DmAuthMessageProcessor::DmAuthUltrasonicMessageProcessor()
{
    LOGI("enter.");
    createMessageFuncMap_[DmMessageType::MSG_TYPE_REVERSE_ULTRASONIC_START] =
        &DmAuthMessageProcessor::CreateMessageReverseUltrasonicStart;
    createMessageFuncMap_[DmMessageType::MSG_TYPE_REVERSE_ULTRASONIC_DONE] =
        &DmAuthMessageProcessor::CreateMessageReverseUltrasonicDone;
    createMessageFuncMap_[DmMessageType::MSG_TYPE_FORWARD_ULTRASONIC_START] =
        &DmAuthMessageProcessor::CreateMessageForwardUltrasonicStart;
    createMessageFuncMap_[DmMessageType::MSG_TYPE_FORWARD_ULTRASONIC_NEGOTIATE] =
        &DmAuthMessageProcessor::CreateMessageForwardUltrasonicNegotiate;

    paraseMessageFuncMap_[DmMessageType::MSG_TYPE_REVERSE_ULTRASONIC_START] =
        &DmAuthMessageProcessor::ParseMessageReverseUltrasonicStart;
    paraseMessageFuncMap_[DmMessageType::MSG_TYPE_REVERSE_ULTRASONIC_DONE] =
        &DmAuthMessageProcessor::ParseMessageReverseUltrasonicDone;
    paraseMessageFuncMap_[DmMessageType::MSG_TYPE_FORWARD_ULTRASONIC_START] =
        &DmAuthMessageProcessor::ParseMessageForwardUltrasonicStart;
    paraseMessageFuncMap_[DmMessageType::MSG_TYPE_FORWARD_ULTRASONIC_NEGOTIATE] =
        &DmAuthMessageProcessor::ParseMessageForwardUltrasonicNegotiate;
    LOGI("leave.");
    return;
}

int32_t DmAuthMessageProcessor::ParseMessageNegotiateTransmit(const JsonObject &jsonObject,
    std::shared_ptr<DmAuthContext> context)
{
    if (jsonObject.IsDiscarded() || !jsonObject.Contains(TAG_DATA) || !jsonObject[TAG_DATA].IsString()) {
        LOGE("Unlegal json string failed");
        return ERR_DM_FAILED;
    }

    context->transmitData = jsonObject[TAG_DATA].Get<std::string>();

    switch (context->msgType) {
        case MSG_TYPE_REQ_CREDENTIAL_AUTH_NEGOTIATE:           // 161
            context->authStateMachine->TransitionTo(std::make_shared<AuthSinkCredentialAuthNegotiateState>());
            break;
        case MSG_TYPE_RESP_CREDENTIAL_AUTH_START:              // 170
            context->authStateMachine->TransitionTo(std::make_shared<AuthSrcCredentialAuthNegotiateState>());
            break;
        case MSG_TYPE_RESP_CREDENTIAL_AUTH_NEGOTIATE:          // 171
            context->authStateMachine->TransitionTo(std::make_shared<AuthSrcCredentialAuthDoneState>());
            break;
        default:
            return ERR_DM_FAILED;
    }

    return DM_OK;
}

int32_t DmAuthMessageProcessor::ParseMessageRespPinAuthNegotiate(const JsonObject &jsonObject,
    std::shared_ptr<DmAuthContext> context)
{
    if (jsonObject.IsDiscarded() || !jsonObject[TAG_DATA].IsString()) {
        LOGE("decodeRequestAuth jsonStr error");
        return ERR_DM_FAILED;
    }

    context->transmitData = jsonObject[TAG_DATA].Get<std::string>();
    context->authStateMachine->TransitionTo(std::make_shared<AuthSrcPinAuthDoneState>());
    return DM_OK;
}

int32_t DmAuthMessageProcessor::ParseMessageReqCredExchange(const JsonObject &jsonObject,
    std::shared_ptr<DmAuthContext> context)
{
    CHECK_NULL_RETURN(cryptoMgr_, ERR_DM_POINT_NULL);
    if (jsonObject.IsDiscarded() || !jsonObject[TAG_DATA].IsString()) {
        LOGE("DecodeRequestAuth jsonStr error");
        return ERR_DM_FAILED;
    }

    std::string plainText;
    if (cryptoMgr_->DecryptMessage(jsonObject[TAG_DATA].Get<std::string>(), plainText) != DM_OK) {
        LOGE("decrypt data failed.");
        return ERR_DM_FAILED;
    }
    JsonObject jsonData(plainText);
    if (jsonData.IsDiscarded()) {
        LOGE("jsonData is discarded after decrypt.");
        return ERR_DM_FAILED;
    }

    // First authentication, parse lnn public key
    if (context->accessee.isGenerateLnnCredential && context->accessee.bindLevel != static_cast<int32_t>(USER)) {
        if (!jsonData[TAG_LNN_PUBLIC_KEY].IsString()) {
            LOGE("first auth, no lnnPublicKey.");
            return ERR_DM_FAILED;
        }
        context->accesser.lnnPublicKey = jsonData[TAG_LNN_PUBLIC_KEY].Get<std::string>();
    }

    if (!jsonData[TAG_TRANSMIT_PUBLIC_KEY].IsString() ||
        !jsonData[TAG_DEVICE_ID].IsString() ||
        !jsonData[TAG_PEER_USER_SPACE_ID].IsNumberInteger() ||
        !jsonData[TAG_TOKEN_ID].IsNumberInteger()) {
        LOGE("MSG_TYPE_REQ_CREDENTIAL_EXCHANGE message error.");
        return ERR_DM_FAILED;
    }
    context->accesser.transmitPublicKey = jsonData[TAG_TRANSMIT_PUBLIC_KEY].Get<std::string>();
    context->accesser.deviceId = jsonData[TAG_DEVICE_ID].Get<std::string>();
    context->accesser.userId = jsonData[TAG_PEER_USER_SPACE_ID].Get<int32_t>();
    context->accesser.tokenId = jsonData[TAG_TOKEN_ID].Get<int64_t>();
    if (jsonData[TAG_ACCOUNT_ID].IsString()) {
        context->accesser.accountId = jsonData[TAG_ACCOUNT_ID].Get<std::string>();
    }
    ParseProxyCredExchangeToSync(context, jsonData);
    context->authStateMachine->TransitionTo(std::make_shared<AuthSinkCredentialExchangeState>());
    return DM_OK;
}

// parse 150
int32_t DmAuthMessageProcessor::ParseMessageRspCredExchange(const JsonObject &jsonObject,
    std::shared_ptr<DmAuthContext> context)
{
    LOGI("start.");
    CHECK_NULL_RETURN(cryptoMgr_, ERR_DM_POINT_NULL);
    if (jsonObject.IsDiscarded() || !jsonObject[TAG_DATA].IsString()) {
        LOGE("DecodeRequestAuth jsonStr error");
        return ERR_DM_FAILED;
    }

    std::string plainText;
    if (cryptoMgr_->DecryptMessage(jsonObject[TAG_DATA].Get<std::string>(), plainText) != DM_OK) {
        LOGE("decrypt data failed.");
        return ERR_DM_FAILED;
    }

    JsonObject jsonData(plainText);
    if (jsonData.IsDiscarded()) {
        LOGE("jsonData is discarded after decrypt.");
        return ERR_DM_FAILED;
    }

    // First authentication, parse lnn public key
    if (context->accesser.isGenerateLnnCredential && context->accesser.bindLevel != static_cast<int32_t>(USER)) {
        if (!jsonData[TAG_LNN_PUBLIC_KEY].IsString()) {
            LOGE("first auth but no lnnPublicKey.");
            return ERR_DM_FAILED;
        }
        context->accessee.lnnPublicKey = jsonData[TAG_LNN_PUBLIC_KEY].Get<std::string>();
    }

    // First authentication, parse transmit public key
    if (!jsonData[TAG_TRANSMIT_PUBLIC_KEY].IsString() ||
        !jsonData[TAG_DEVICE_ID].IsString() ||
        !jsonData[TAG_PEER_USER_SPACE_ID].IsNumberInteger() ||
        !jsonData[TAG_TOKEN_ID].IsNumberInteger()) {
        LOGE("decode MSG_TYPE_RESP_CREDENTIAL_EXCHANGE"
            "message error.");
        return ERR_DM_FAILED;
    }
    context->accessee.transmitPublicKey = jsonData[TAG_TRANSMIT_PUBLIC_KEY].Get<std::string>();
    context->accessee.deviceId = jsonData[TAG_DEVICE_ID].Get<std::string>();
    context->accessee.userId = jsonData[TAG_PEER_USER_SPACE_ID].Get<int32_t>();
    context->accessee.tokenId = jsonData[TAG_TOKEN_ID].Get<int64_t>();
    if (jsonData[TAG_ACCOUNT_ID].IsString()) {
        context->accessee.accountId = jsonData[TAG_ACCOUNT_ID].Get<std::string>();
    }
    ParseProxyCredExchangeToSync(context, jsonData);
    context->authStateMachine->TransitionTo(std::make_shared<AuthSrcCredentialAuthStartState>());
    return DM_OK;
}

// parse 141
int32_t DmAuthMessageProcessor::ParseMessageReqSKDerive(const JsonObject &jsonObject,
    std::shared_ptr<DmAuthContext> context)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(cryptoMgr_, ERR_DM_POINT_NULL);
    if (jsonObject.IsDiscarded() || !jsonObject[TAG_DATA].IsString()) {
        LOGE("DecodeRequestAuth jsonStr error");
        return ERR_DM_FAILED;
    }
    std::string plainText;
    if (cryptoMgr_->DecryptMessage(jsonObject[TAG_DATA].Get<std::string>(), plainText) != DM_OK) {
        LOGE("decrypt data failed.");
        return ERR_DM_FAILED;
    }
    JsonObject jsonData(plainText);
    if (jsonData.IsDiscarded()) {
        LOGE("jsonData is discarded after decrypt.");
        return ERR_DM_FAILED;
    }
    // First authentication, parse lnn public key
    if (context->accessee.isGenerateLnnCredential && context->accessee.bindLevel != static_cast<int32_t>(USER)) {
        if (!jsonData[TAG_LNN_CREDENTIAL_ID].IsString()) {
            LOGE("first auth, no lnnPublicKey.");
            return ERR_DM_FAILED;
        }
        context->accesser.lnnCredentialId = jsonData[TAG_LNN_CREDENTIAL_ID].Get<std::string>();
    }
    if (!jsonData[TAG_TRANSMIT_CREDENTIAL_ID].IsString()) {
        LOGE("MSG_TYPE_REQ_SK_DERIVE message error.");
        return ERR_DM_FAILED;
    }
    context->accesser.transmitCredentialId = jsonData[TAG_TRANSMIT_CREDENTIAL_ID].Get<std::string>();
    context->authStateMachine->TransitionTo(std::make_shared<AuthSinkSKDeriveState>());
    return DM_OK;
}

// parse 151
int32_t DmAuthMessageProcessor::ParseMessageRspSKDerive(const JsonObject &jsonObject,
    std::shared_ptr<DmAuthContext> context)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(cryptoMgr_, ERR_DM_POINT_NULL);
    if (jsonObject.IsDiscarded() || !jsonObject[TAG_DATA].IsString()) {
        LOGE("DecodeRequestAuth jsonStr error");
        return ERR_DM_FAILED;
    }
    std::string plainText;
    if (cryptoMgr_->DecryptMessage(jsonObject[TAG_DATA].Get<std::string>(), plainText) != DM_OK) {
        LOGE("decrypt data failed.");
        return ERR_DM_FAILED;
    }
    JsonObject jsonData(plainText);
    if (jsonData.IsDiscarded()) {
        LOGE("jsonData is discarded after decrypt.");
        return ERR_DM_FAILED;
    }
    // First authentication, parse lnn public key
    if (context->accesser.isGenerateLnnCredential && context->accesser.bindLevel != static_cast<int32_t>(USER)) {
        if (!jsonData[TAG_LNN_CREDENTIAL_ID].IsString()) {
            LOGE("first auth, no lnnPublicKey.");
            return ERR_DM_FAILED;
        }
        context->accessee.lnnCredentialId = jsonData[TAG_LNN_CREDENTIAL_ID].Get<std::string>();
    }
    if (!jsonData[TAG_TRANSMIT_CREDENTIAL_ID].IsString()) {
        LOGE("MSG_TYPE_RESP_SK_DERIVE message error.");
        return ERR_DM_FAILED;
    }
    context->accessee.transmitCredentialId = jsonData[TAG_TRANSMIT_CREDENTIAL_ID].Get<std::string>();
    context->authStateMachine->TransitionTo(std::make_shared<AuthSrcSKDeriveState>());
    return DM_OK;
}
int32_t DmAuthMessageProcessor::ParseProxyCredExchangeToSync(std::shared_ptr<DmAuthContext> &context,
    JsonObject &jsonObject)
{
    LOGI("inner1");
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    auto &targetList = context->isServiceBind ? context->subjectServiceOnes : context->subjectProxyOnes;
    auto targetKey = context->isServiceBind ? PARAM_KEY_SUBJECT_SERVICE_ONES : PARAM_KEY_SUBJECT_PROXYED_SUBJECTS;
    if (!context->IsProxyBind || targetList.empty()) {
        LOGI("inner2");
        return DM_OK;
    }
    if (!IsString(jsonObject, targetKey)) {
        LOGE("no subjectProxyOnes");
        return ERR_DM_FAILED;
    }
    std::string subjectProxyOnesStr = jsonObject[targetKey].Get<std::string>();
    JsonObject allProxyObj;
    if (!allProxyObj.Parse(subjectProxyOnesStr) || allProxyObj.IsDiscarded()) {
        LOGE("subjectProxyOnes json parse failed.");
        return ERR_DM_FAILED;
    }
    for (auto const &item : allProxyObj.Items()) {
        if (!IsString(item, TAG_PROXY_CONTEXT_ID)) {
            continue;
        }
        DmProxyAuthContext proxyAuthContext;
        proxyAuthContext.proxyContextId = item[TAG_PROXY_CONTEXT_ID].Get<std::string>();
        auto it = std::find(targetList.begin(), targetList.end(), proxyAuthContext);
        if (it != targetList.end()) {
            if (!IsInt64(item, TAG_TOKEN_ID)) {
                LOGE("no tokenId");
                return ERR_DM_FAILED;
            }
            DmProxyAccess &access = (context->direction == DM_AUTH_SOURCE) ? it->proxyAccessee : it->proxyAccesser;
            access.tokenId = item[TAG_TOKEN_ID].Get<int64_t>();
        }
    }
    return DM_OK;
}

std::string DmAuthMessageProcessor::CreateMessage(DmMessageType msgType, std::shared_ptr<DmAuthContext> context)
{
    LOGI("start. msgType is %{public}d", msgType);
    if (context == nullptr) {
        LOGE("context is nullptr.");
        return "";
    }
    JsonObject jsonObj;
    jsonObj[TAG_MSG_TYPE] = msgType;
    jsonObj[DM_TAG_LOGICAL_SESSION_ID] = context->logicalSessionId;
    auto itr = createMessageFuncMap_.find(msgType);
    if (itr == createMessageFuncMap_.end()) {
        LOGE("msgType %{public}d error.", msgType);
        return "";
    }
    int32_t ret = (this->*(itr->second))(context, jsonObj);
    LOGI("start. message is %{public}s", GetAnonyJsonString(jsonObj.Dump()).c_str());
    return (ret == DM_OK) ? jsonObj.Dump() : "";
}

int32_t DmAuthMessageProcessor::CreateCredentialNegotiateMessage(std::shared_ptr<DmAuthContext> context,
    JsonObject &jsonObject)
{
    jsonObject[TAG_DATA] = context->transmitData;
    return DM_OK;
}

int32_t DmAuthMessageProcessor::CreateNegotiateOldMessage(std::shared_ptr<DmAuthContext> context,
    JsonObject &jsonObject)
{
    jsonObject[TAG_CRYPTO_SUPPORT] = false;
    jsonObject[TAG_AUTH_TYPE] = context->authType;
    jsonObject[TAG_REPLY] = context->reply;
    jsonObject[TAG_LOCAL_DEVICE_ID] = context->accesser.deviceId;
    jsonObject[TAG_ACCOUNT_GROUPID] = context->accesser.accountGroupIdHash;

    jsonObject[TAG_BIND_LEVEL] = context->accesser.oldBindLevel;    // compatible issue
    jsonObject[TAG_LOCAL_ACCOUNTID] = context->accesser.accountId;
    jsonObject[TAG_LOCAL_USERID] = context->accesser.userId;
    jsonObject[TAG_ISONLINE] = false;
    jsonObject[TAG_AUTHED] = false;
    jsonObject[TAG_HOST] = context->pkgName;
    jsonObject[TAG_TOKENID] = context->accesser.tokenId;
    jsonObject[TAG_IDENTICAL_ACCOUNT] = false;
    jsonObject[TAG_HAVE_CREDENTIAL] = false;
    jsonObject[TAG_REMOTE_DEVICE_NAME] = context->accesser.deviceName;

    return DM_OK;
}

// Create 80 message.
// LCOV_EXCL_START
int32_t DmAuthMessageProcessor::CreateNegotiateMessage(std::shared_ptr<DmAuthContext> context,
    JsonObject &jsonObject)
{
    // create old message for compatible in import auth code
    if (context->authType == DmAuthType::AUTH_TYPE_IMPORT_AUTH_CODE) {
        CreateNegotiateOldMessage(context, jsonObject);
    }
    jsonObject[TAG_DMVERSION] = "";
    jsonObject[TAG_EDITION] = DM_VERSION_5_0_5;
    jsonObject[TAG_BUNDLE_NAME] = context->accesser.bundleName;
    jsonObject[TAG_PEER_BUNDLE_NAME] = context->accessee.oldBundleName;
    jsonObject[TAG_PKG_NAME] = context->pkgName;
    jsonObject[TAG_DM_VERSION_V2] = context->accesser.dmVersion;
    jsonObject[TAG_USER_ID] = context->accesser.userId;
    jsonObject[TAG_DEVICE_NAME] = context->accesser.deviceName;
    jsonObject[TAG_DEVICE_ID_HASH] = context->accesser.deviceIdHash;
    jsonObject[TAG_ACCOUNT_ID_HASH] = context->accesser.accountIdHash;
    jsonObject[TAG_TOKEN_ID_HASH] = context->accesser.tokenIdHash;
    jsonObject[TAG_BUNDLE_NAME_V2] = context->accesser.bundleName;
    jsonObject[TAG_EXTRA_INFO] = context->accesser.extraInfo;
    jsonObject[TAG_PEER_BUNDLE_NAME_V2] = context->accessee.bundleName;
    jsonObject[TAG_ULTRASONIC_SIDE] = static_cast<int32_t>(context->ultrasonicInfo);
    jsonObject[TAG_PEER_DISPLAY_ID] = context->accessee.displayId;
    jsonObject[TAG_PEER_PKG_NAME] = context->accessee.pkgName;
    jsonObject[TAG_HOST_PKGLABEL] = context->pkgLabel;
    jsonObject[TAG_SERVICE_ID] = context->accessee.serviceId;
    jsonObject[PARAM_KEY_IS_SERVICE_BIND] = context->isServiceBind;
    jsonObject[TAG_DEVICE_TYPE] = context->accesser.deviceType;
    jsonObject[TAG_PEER_USER_ID] = context->accessee.userId;
    if (!context->businessId.empty()) {
        jsonObject[DM_BUSINESS_ID] = context->businessId;
    }
    jsonObject[TAG_NCM_BIND_TARGET] = context->ncmBindTarget;
    if (context->isServiceBind) {
        CreateServiceNegotiateMessage(context, jsonObject);
        return DM_OK;
    }
    CreateProxyNegotiateMessage(context, jsonObject);
    return DM_OK;
}

int32_t DmAuthMessageProcessor::CreateServiceNegotiateMessage(std::shared_ptr<DmAuthContext> context,
    JsonObject &jsonObject)
{
    LOGI("inner1");
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    jsonObject[TAG_SERVICE_CODE] = context->accessee.serviceCode;
    jsonObject[PARAM_KEY_IS_PROXY_BIND] = context->IsProxyBind;
    jsonObject[PARAM_KEY_IS_CALLING_PROXY_AS_SUBJECT] = context->IsCallingProxyAsSubject;
    if (context != nullptr && context->IsProxyBind && !context->subjectServiceOnes.empty()) {
        jsonObject[TAG_AUTH_TYPE] = context->authType;
        JsonObject allProxyObj(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
        for (const auto &app : context->subjectServiceOnes) {
            JsonObject object;
            object[TAG_PROXY_CONTEXT_ID] = app.proxyContextId;
            object[TAG_HOST_PKGLABEL] = app.pkgLabel;
            object[TAG_PKG_NAME] = app.proxyAccesser.pkgName;
            object[TAG_TOKEN_ID] = app.proxyAccesser.tokenId;
            object[TAG_TOKEN_ID_HASH] = app.proxyAccesser.tokenIdHash;
            object[TAG_SERVICE_ID] = app.proxyAccessee.serviceId;
            allProxyObj.PushBack(object);
        }
        jsonObject[PARAM_KEY_SUBJECT_SERVICE_ONES] = allProxyObj.Dump();
    }
    return DM_OK;
}
// LCOV_EXCL_STOP
int32_t DmAuthMessageProcessor::CreateProxyNegotiateMessage(std::shared_ptr<DmAuthContext> context,
    JsonObject &jsonObject)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    jsonObject[PARAM_KEY_IS_PROXY_BIND] = context->IsProxyBind;
    jsonObject[PARAM_KEY_IS_CALLING_PROXY_AS_SUBJECT] = context->IsCallingProxyAsSubject;
    if (context != nullptr && context->IsProxyBind && !context->subjectProxyOnes.empty()) {
        jsonObject[TAG_AUTH_TYPE] = context->authType;
        JsonObject allProxyObj(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
        for (const auto &app : context->subjectProxyOnes) {
            JsonObject object;
            object[TAG_PROXY_CONTEXT_ID] = app.proxyContextId;
            object[TAG_HOST_PKGLABEL] = app.pkgLabel;
            object[TAG_BUNDLE_NAME] = app.proxyAccesser.bundleName;
            object[TAG_PEER_BUNDLE_NAME] = app.proxyAccessee.bundleName;
            object[TAG_TOKEN_ID_HASH] = app.proxyAccesser.tokenIdHash;
            allProxyObj.PushBack(object);
        }
        jsonObject[PARAM_KEY_SUBJECT_PROXYED_SUBJECTS] = allProxyObj.Dump();
    }
    return DM_OK;
}

// Create 90 message.
int32_t DmAuthMessageProcessor::CreateRespNegotiateMessage(std::shared_ptr<DmAuthContext> context,
    JsonObject &jsonObject)
{
    jsonObject[TAG_DEVICE_VERSION] = context->accessee.dmVersion;
    jsonObject[TAG_DEVICE_NAME] = context->accessee.deviceName;

    jsonObject[TAG_DEVICE_ID_HASH] = context->accessee.deviceIdHash;
    jsonObject[TAG_ACCOUNT_ID_HASH] = context->accessee.accountIdHash;
    jsonObject[TAG_TOKEN_ID_HASH] = context->accessee.tokenIdHash;
    jsonObject[TAG_USER_ID] = context->accessee.userId;
    jsonObject[TAG_ACL_TYPE_LIST] = context->accessee.aclTypeList;
    jsonObject[TAG_CERT_TYPE_LIST] = context->accessee.credTypeList;
    jsonObject[TAG_LANGUAGE] = context->accessee.language;
    jsonObject[TAG_EXTRA_INFO] = context->accessee.extraInfo;
    jsonObject[TAG_NETWORKID_ID] = context->accessee.networkId;
    jsonObject[TAG_CERT_RANDOM] = context->accessee.certRandom;
    jsonObject[TAG_SERVICE_ID] = context->accessee.serviceId;

    jsonObject[TAG_IS_ONLINE] = context->accesser.isOnline;
    jsonObject[TAG_DEVICE_TYPE] = context->accessee.deviceType;
    CreateProxyRespNegotiateMessage(context, jsonObject);
    return DM_OK;
}
int32_t DmAuthMessageProcessor::CreateProxyRespNegotiateMessage(std::shared_ptr<DmAuthContext> context,
    JsonObject &jsonObject)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    auto &targetList = context->isServiceBind ? context->subjectServiceOnes : context->subjectProxyOnes;
    auto targetKey = context->isServiceBind ? PARAM_KEY_SUBJECT_SERVICE_ONES : PARAM_KEY_SUBJECT_PROXYED_SUBJECTS;
    jsonObject[PARAM_KEY_IS_PROXY_BIND] = context->IsProxyBind;
    if (context->IsProxyBind && !targetList.empty()) {
        JsonObject allProxyObj(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
        for (const auto &app : targetList) {
            JsonObject object;
            object[TAG_PROXY_CONTEXT_ID] = app.proxyContextId;
            object[TAG_SERVICE_ID] = app.proxyAccessee.serviceId;
            object[TAG_TOKEN_ID_HASH] = app.proxyAccessee.tokenIdHash;
            object[TAG_ACL_TYPE_LIST] = app.proxyAccessee.aclTypeList;
            object[TAG_CERT_TYPE_LIST] = app.proxyAccessee.credTypeList;
            object[TAG_BUNDLE_NAME] = app.proxyAccessee.bundleName;
            allProxyObj.PushBack(object);
        }
        jsonObject[targetKey] = allProxyObj.Dump();
    }
    return DM_OK;
}

// Create 140 message.
int32_t DmAuthMessageProcessor::CreateMessageReqCredExchange(std::shared_ptr<DmAuthContext> context,
    JsonObject &jsonObject)
{
    CHECK_NULL_RETURN(cryptoMgr_, ERR_DM_POINT_NULL);
    JsonObject jsonData;
    if (context->accesser.isGenerateLnnCredential && context->accesser.bindLevel != static_cast<int32_t>(USER)) {
        jsonData[TAG_LNN_PUBLIC_KEY] = context->accesser.lnnPublicKey;
    }
    jsonData[TAG_TRANSMIT_PUBLIC_KEY] = context->accesser.transmitPublicKey;
    jsonData[TAG_DEVICE_ID] = context->accesser.deviceId;
    jsonData[TAG_PEER_USER_SPACE_ID] = context->accesser.userId;
    jsonData[TAG_TOKEN_ID] = context->accesser.tokenId;
    jsonData[TAG_ACCOUNT_ID] = context->accesser.accountId;
    CreateProxyCredExchangeMessage(context, jsonData);
    std::string plainText = jsonData.Dump();
    std::string cipherText;
    int32_t ret = cryptoMgr_->EncryptMessage(plainText, cipherText);
    if (ret != DM_OK) {
        LOGI("encryptMessage failed.");
        return ret;
    }
    jsonObject[TAG_DATA] = cipherText;
    return ret;
}

// Create 150 message.
int32_t DmAuthMessageProcessor::CreateMessageRspCredExchange(std::shared_ptr<DmAuthContext> context,
    JsonObject &jsonObject)
{
    LOGI("start.");
    CHECK_NULL_RETURN(cryptoMgr_, ERR_DM_POINT_NULL);
    JsonObject jsonData;
    if (context->accessee.isGenerateLnnCredential && context->accessee.bindLevel != static_cast<int32_t>(USER)) {
        jsonData[TAG_LNN_PUBLIC_KEY] = context->accessee.lnnPublicKey;
    }
    jsonData[TAG_TRANSMIT_PUBLIC_KEY] = context->accessee.transmitPublicKey;
    jsonData[TAG_DEVICE_ID] = context->accessee.deviceId;
    jsonData[TAG_PEER_USER_SPACE_ID] = context->accessee.userId;
    jsonData[TAG_TOKEN_ID] = context->accessee.tokenId;
    jsonData[TAG_ACCOUNT_ID] = context->accessee.accountId;
    CreateProxyCredExchangeMessage(context, jsonData);
    std::string plainText = jsonData.Dump();
    std::string cipherText;
    LOGI("plainText=%{public}s", GetAnonyJsonString(plainText).c_str());
    int32_t ret = cryptoMgr_->EncryptMessage(plainText, cipherText);
    if (ret != DM_OK) {
        LOGI("encryptMessage failed.");
        return ret;
    }
    jsonObject[TAG_DATA] = cipherText;
    return ret;
}
int32_t DmAuthMessageProcessor::CreateProxyCredExchangeMessage(std::shared_ptr<DmAuthContext> &context,
    JsonObject &jsonData)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    auto &targetList = context->isServiceBind ? context->subjectServiceOnes : context->subjectProxyOnes;
    auto targetKey = context->isServiceBind ? PARAM_KEY_SUBJECT_SERVICE_ONES : PARAM_KEY_SUBJECT_PROXYED_SUBJECTS;
    if (!context->IsProxyBind || targetList.empty()) {
        return DM_OK;
    }
    JsonObject allProxyObj(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
    for (const auto &app : targetList) {
        const DmProxyAccess &access = (context->direction == DM_AUTH_SOURCE) ? app.proxyAccesser : app.proxyAccessee;
        JsonObject object;
        object[TAG_PROXY_CONTEXT_ID] = app.proxyContextId;
        object[TAG_TOKEN_ID] = access.tokenId;
        allProxyObj.PushBack(object);
    }
    jsonData[targetKey ] = allProxyObj.Dump();
    return DM_OK;
}

//LCOV_EXCL_START
// Create 141 message.
int32_t DmAuthMessageProcessor::CreateMessageReqSKDerive(std::shared_ptr<DmAuthContext> context,
    JsonObject &jsonObject)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(cryptoMgr_, ERR_DM_POINT_NULL);
    JsonObject jsonData;
    jsonData[TAG_TRANSMIT_CREDENTIAL_ID] = context->accesser.transmitCredentialId;
    // First certification
    if (context->accesser.isGenerateLnnCredential && context->accesser.bindLevel != static_cast<int32_t>(USER)) {
        jsonData[TAG_LNN_CREDENTIAL_ID] = context->accesser.lnnCredentialId;
    }
    std::string plainText = jsonData.Dump();
    std::string cipherText;
    int32_t ret = cryptoMgr_->EncryptMessage(plainText, cipherText);
    if (ret != DM_OK) {
        LOGE("encryptMessage failed.");
        return ret;
    }
    jsonObject[TAG_DATA] = cipherText;
    return ret;
}

// Create 151 message.
int32_t DmAuthMessageProcessor::CreateMessageRspSKDerive(std::shared_ptr<DmAuthContext> context,
    JsonObject &jsonObject)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    CHECK_NULL_RETURN(cryptoMgr_, ERR_DM_POINT_NULL);
    JsonObject jsonData;
    jsonData[TAG_TRANSMIT_CREDENTIAL_ID] = context->accessee.transmitCredentialId;
    // First certification
    if (context->accessee.isGenerateLnnCredential && context->accessee.bindLevel != static_cast<int32_t>(USER)) {
        jsonData[TAG_LNN_CREDENTIAL_ID] = context->accessee.lnnCredentialId;
    }
    std::string plainText = jsonData.Dump();
    std::string cipherText;
    int32_t ret = cryptoMgr_->EncryptMessage(plainText, cipherText);
    if (ret != DM_OK) {
        LOGE("encryptMessage failed.");
        return ret;
    }
    jsonObject[TAG_DATA] = cipherText;
    return ret;
}
//LCOV_EXCL_STOP

// Create 160 message.
int32_t DmAuthMessageProcessor::CreateMessageReqCredAuthStart(std::shared_ptr<DmAuthContext> context,
    JsonObject &jsonObject)
{
    JsonObject jsonData;
    jsonObject[TAG_DATA] = context->transmitData;
    return DM_OK;
}

// Create 190 message.
int32_t DmAuthMessageProcessor::CreateMessageSyncResp(std::shared_ptr<DmAuthContext> context,
    JsonObject &jsonObject)
{
    DmAccess access;
    if (context->direction == DM_AUTH_SINK) {
        access = context->accessee;
    } else {
        access = context->accesser;
    }

    std::string encSyncMsg;
    int32_t ret = EncryptSyncMessage(context, access, encSyncMsg);
    if (ret != DM_OK) {
        LOGE("encrypt failed");
        return ret;
    }
    jsonObject[TAG_SYNC] = encSyncMsg;
    return ret;
}

// Create 200 message.
int32_t DmAuthMessageProcessor::CreateMessageFinish(std::shared_ptr<DmAuthContext> context,
    JsonObject &jsonObject)
{
    jsonObject[TAG_REPLY] = context->reply;
    jsonObject[TAG_REASON] = context->reason;
    jsonObject[TAG_REMAINING_FROZEN_TIME] = context->remainingFrozenTime;
    return DM_OK;
}

bool DmAuthMessageProcessor::CheckAccessValidityAndAssign(std::shared_ptr<DmAuthContext> &context, DmAccess &access,
    DmAccess &accessTmp)
{
    const DmAccess &selfAccess = (context->direction == DM_AUTH_SOURCE) ? context->accesser : context->accessee;

    bool isSame = accessTmp.dmVersion == access.dmVersion &&
        accessTmp.deviceName == access.deviceName &&
        Crypto::GetUdidHash(accessTmp.deviceId) == access.deviceIdHash &&
        accessTmp.userId == access.userId &&
        Crypto::GetAccountIdHash16(accessTmp.accountId) == access.accountIdHash &&
        Crypto::GetTokenIdHash(std::to_string(accessTmp.tokenId)) == access.tokenIdHash &&
        accessTmp.bundleName == access.bundleName &&
        accessTmp.pkgName == access.pkgName &&
        accessTmp.bindLevel == selfAccess.bindLevel &&
        accessTmp.serviceId == context->accessee.serviceId;
    if (isSame) {
        access.transmitSessionKeyId = accessTmp.transmitSessionKeyId;
        access.transmitSkTimeStamp = accessTmp.transmitSkTimeStamp;
        access.transmitCredentialId = accessTmp.transmitCredentialId;
        access.lnnSessionKeyId = accessTmp.lnnSessionKeyId;
        access.lnnSkTimeStamp = accessTmp.lnnSkTimeStamp;
        access.lnnCredentialId = accessTmp.lnnCredentialId;
        access.tokenId = accessTmp.tokenId;
    }
    return isSame;
}
int32_t DmAuthMessageProcessor::ParseSyncMessage(std::shared_ptr<DmAuthContext> &context,
    DmAccess &access, JsonObject &jsonObject)
{
    DmAccess accessTmp;
    if (ParseInfoToDmAccess(jsonObject, accessTmp) != DM_OK) {
        LOGE("Parse DataSync prarm err");
        return ERR_DM_FAILED;
    }

    if (!IsString(jsonObject, TAG_ACCESS)) {
        LOGE("TAG_ACCESS error");
        return ERR_DM_FAILED;
    }
    std::string srcAccessStr = jsonObject[TAG_ACCESS].Get<std::string>();
    // Parse into access
    if (!ParseDmAccessToSync(srcAccessStr, accessTmp, false)) {
        LOGE("ParseDmAccessToSync accessTmp failed, stop auth.");
        return ERR_DM_FAILED;
    }
    // check access validity
    if (ParseProxyAccessToSync(context, jsonObject) != DM_OK) {
        LOGE("ParseProxyAccessToSync error, stop auth.");
        return ERR_DM_FAILED;
    }
    if (!CheckAccessValidityAndAssign(context, access, accessTmp)) {
        LOGE("CheckAccessValidityAndAssign error, data between two stages different, stop auth.");
        return ERR_DM_FAILED;
    }
    if (!ParseDmAccessToSync(srcAccessStr, access, true)) {
        LOGE("ParseDmAccessToSync access failed, stop auth.");
        return ERR_DM_FAILED;
    }
    if (!IsString(jsonObject, TAG_ACL_CHECKSUM)) { // Re-parse the acl
        LOGE("TAG_ACL_CHECKSUM error");
        return ERR_DM_FAILED;
    }
    access.aclStrList = jsonObject[TAG_ACL_CHECKSUM].Get<std::string>();
    ParseSinkUserConfirmOpt(context, jsonObject);
    if (IsBool(jsonObject, PIN_MATCH_FLAG)) {
        context->pinCodeFlag = jsonObject[PIN_MATCH_FLAG].Get<bool>();
    }
    if (IsBool(jsonObject, TAG_NCM_BIND_TARGET)) {
        context->ncmBindTarget = jsonObject[TAG_NCM_BIND_TARGET].Get<bool>();
    }
    ParseCert(jsonObject, context);
    if (context->isServiceBind) {
        ParseServiceInfo(jsonObject, context);
    }
    return DM_OK;
}
// LCOV_EXCL_START
void DmAuthMessageProcessor::ParseServiceInfo(JsonObject &jsonObject, std::shared_ptr<DmAuthContext> &context)
{
    LOGI("start");
    if (!IsString(jsonObject, TAG_SERVICE_INFOS)) {
        LOGI("no serviceInfos");
        return;
    }
    std::string serviceInfosStr = jsonObject[TAG_SERVICE_INFOS].Get<std::string>();
    JsonObject allServiceInfo;
    if (!allServiceInfo.Parse(serviceInfosStr) || allServiceInfo.IsDiscarded()) {
        LOGE("Failed to parse serviceInfosStr");
        return;
    }
    for (auto const &item : allServiceInfo.Items()) {
        if (!CheckServiceInfoItem(item)) {
            LOGE("serviceInfo item format error, stop parsing.");
            return;
        }
        DistributedDeviceProfile::ServiceInfo info;
        FillServiceInfoFromItem(item, info);
        context->serviceInfos.push_back(info);
    }
    if (!IsString(jsonObject, TAG_SERVICE_ID)) {
        LOGE("TAG_SERVICE_ID error");
        return;
    }
    std::string serviceIdStr = jsonObject[TAG_SERVICE_ID].Get<std::string>();
    JsonObject allServiceId;
    if (!allServiceId.Parse(serviceIdStr) || allServiceId.IsDiscarded()) {
        LOGE("Failed to parse serviceIdStr");
        return;
    }
    for (auto &id : allServiceId.Items()) {
        if (!id.IsNumberInteger()) {
            LOGE("serviceId item is not integer, stop parsing.");
            return;
        }
        context->serviceId.push_back(id.Get<int64_t>());
    }
}

static int32_t ParseServiceProxyAccessToSync(std::shared_ptr<DmAuthContext> &context, JsonObject &jsonObject)
{
    std::string subjectProxyOnesStr = jsonObject[PARAM_KEY_SUBJECT_SERVICE_ONES].Get<std::string>();
    JsonObject allProxyObj;
    if (!allProxyObj.Parse(subjectProxyOnesStr) || allProxyObj.IsDiscarded()) {
        LOGE("subjectProxyOnesStr parse failed.");
        return ERR_DM_FAILED;
    }
    for (auto const &item : allProxyObj.Items()) {
        if (!IsString(item, TAG_PROXY_CONTEXT_ID)) {
            LOGE("no proxyContextId");
            return ERR_DM_FAILED;
        }
        DmProxyAuthContext proxyAuthContext;
        proxyAuthContext.proxyContextId = item[TAG_PROXY_CONTEXT_ID].Get<std::string>();
        auto it = std::find(context->subjectServiceOnes.begin(), context->subjectServiceOnes.end(), proxyAuthContext);
        if (it != context->subjectServiceOnes.end()) {
            if (!CheckServiceProxyItemFields(item)) {
                LOGE("proxyContext format error");
                return ERR_DM_FAILED;
            }

            DmProxyAccess &access = (context->direction == DM_AUTH_SOURCE) ? it->proxyAccessee : it->proxyAccesser;
            DmProxyAccess &selfAccess = (context->direction == DM_AUTH_SOURCE) ? it->proxyAccesser : it->proxyAccessee;
            if (Crypto::GetTokenIdHash(std::to_string(item[TAG_TOKEN_ID].Get<int64_t>())) == access.tokenIdHash &&
                item[TAG_BIND_LEVEL].Get<int32_t>() == selfAccess.bindLevel &&
                item[TAG_SRC_SUBJECT_PKGNAME].Get<std::string>() == it->proxyAccesser.pkgName &&
                item[TAG_SUBJECT_SERVICEID].Get<int64_t>() == it->proxyAccessee.serviceId) {
                access.tokenId  = item[TAG_TOKEN_ID].Get<int64_t>();
                access.bindLevel = item[TAG_BIND_LEVEL].Get<int32_t>();
                access.transmitSessionKeyId = std::atoi(item[TAG_TRANSMIT_SK_ID].Get<std::string>().c_str());
                access.skTimeStamp = item[TAG_TRANSMIT_SK_TIMESTAMP].Get<int64_t>();
                access.transmitCredentialId  = item[TAG_TRANSMIT_CREDENTIAL_ID].Get<std::string>();
            } else {
                LOGE("tokenId or bindLevel invaild");
                return ERR_DM_FAILED;
            }
        } else {
            LOGE("proxyContextId not exist");
            return ERR_DM_FAILED;
        }
    }
    return DM_OK;
}

static int32_t ParseDeviceProxyAccessToSync(std::shared_ptr<DmAuthContext> &context, JsonObject &jsonObject)
{
    std::string subjectProxyOnesStr = jsonObject[PARAM_KEY_SUBJECT_PROXYED_SUBJECTS].Get<std::string>();
    JsonObject allProxyObj;
    if (!allProxyObj.Parse(subjectProxyOnesStr) || allProxyObj.IsDiscarded()) {
        LOGE("subjectProxyOnesStr parse failed.");
        return ERR_DM_FAILED;
    }
    for (auto const &item : allProxyObj.Items()) {
        if (!IsString(item, TAG_PROXY_CONTEXT_ID)) {
            LOGE("no proxyContextId");
            return ERR_DM_FAILED;
        }
        DmProxyAuthContext proxyAuthContext;
        proxyAuthContext.proxyContextId = item[TAG_PROXY_CONTEXT_ID].Get<std::string>();
        auto it = std::find(context->subjectProxyOnes.begin(), context->subjectProxyOnes.end(), proxyAuthContext);
        if (it != context->subjectProxyOnes.end()) {
            if (!CheckDeviceProxyItemFields(item)) {
                LOGE("proxyContext format error");
                return ERR_DM_FAILED;
            }
            DmProxyAccess &access = (context->direction == DM_AUTH_SOURCE) ? it->proxyAccessee : it->proxyAccesser;
            DmProxyAccess &selfAccess = (context->direction == DM_AUTH_SOURCE) ? it->proxyAccesser : it->proxyAccessee;
            if (Crypto::GetTokenIdHash(std::to_string(item[TAG_TOKEN_ID].Get<int64_t>())) == access.tokenIdHash &&
                item[TAG_BIND_LEVEL].Get<int32_t>() == selfAccess.bindLevel) {
                access.tokenId  = item[TAG_TOKEN_ID].Get<int64_t>();
                access.bindLevel = item[TAG_BIND_LEVEL].Get<int32_t>();
                access.transmitSessionKeyId = std::atoi(item[TAG_TRANSMIT_SK_ID].Get<std::string>().c_str());
                access.skTimeStamp = item[TAG_TRANSMIT_SK_TIMESTAMP].Get<int64_t>();
                access.transmitCredentialId  = item[TAG_TRANSMIT_CREDENTIAL_ID].Get<std::string>();
            } else {
                LOGE("tokenId or bindLevel invaild");
                return ERR_DM_FAILED;
            }
        } else {
            LOGE("proxyContextId not exist");
            return ERR_DM_FAILED;
        }
    }
    return DM_OK;
}

int32_t DmAuthMessageProcessor::ParseProxyAccessToSync(std::shared_ptr<DmAuthContext> &context,
    JsonObject &jsonObject)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    auto &targetList = context->isServiceBind ? context->subjectServiceOnes : context->subjectProxyOnes;
    auto targetKey = context->isServiceBind ? PARAM_KEY_SUBJECT_SERVICE_ONES : PARAM_KEY_SUBJECT_PROXYED_SUBJECTS;
    if (!context->IsProxyBind || targetList.empty()) {
        return DM_OK;
    }
    if (!IsString(jsonObject, targetKey)) {
        LOGE("no subjectProxyOnes");
        return ERR_DM_FAILED;
    }
    if (context->isServiceBind) {
        return ParseServiceProxyAccessToSync(context, jsonObject);
    } else {
        return ParseDeviceProxyAccessToSync(context, jsonObject);
    }
}
// LCOV_EXCL_STOP

} // namespace DistributedHardware
} // namespace OHOS
