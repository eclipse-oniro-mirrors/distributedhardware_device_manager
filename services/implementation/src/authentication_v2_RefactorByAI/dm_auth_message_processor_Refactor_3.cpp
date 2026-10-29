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

#include "dm_auth_message_processor.h"

#include <algorithm>
#include <sstream>

#include "dm_log.h"
#include "dm_constants.h"
#include "dm_anonymous.h"
#include "dm_auth_manager_base.h"
#include "dm_auth_context.h"
#include "dm_auth_state_machine.h"

#ifdef SUPPORT_MSDP
#include "spatial_awareness_mgr_client.h"
#endif

namespace OHOS {
namespace DistributedHardware {

// Json keys and values used by this file only and not declared in any public header.
constexpr const char* TAG_DEVICE_TYPE = "DEVICETYPE";
constexpr const char* TAG_NCM_BIND_TARGET = "ncm_bind_target";
constexpr const char* TAG_ACL_TYPE_LIST = "aclTypeList";
constexpr const char* TAG_CERT_TYPE_LIST = "certTypeList";
constexpr const char* TAG_REMAINING_FROZEN_TIME = "remainingFrozenTime";
constexpr const char* TAG_CUSTOM_DESCRIPTION = "CUSTOMDESC";
constexpr const char* TAG_IS_SUPPORT_ULTRASONIC = "isSupportUltrasonic";
constexpr const char* TAG_PKG_NAME = "pkgName";
constexpr int32_t DM_ULTRASONIC_FORWARD = 0;
constexpr int32_t DM_ULTRASONIC_REVERSE = 1;

static std::vector<DmAuthType> stringToVectorAuthType(const std::string &str)
{
    std::vector<DmAuthType> vec;
    std::istringstream iss(str);
    int32_t num;
    while (iss >> num) {
        vec.push_back(static_cast<DmAuthType>(num));
    }
    return vec;
}

int32_t DmAuthMessageProcessor::ParseMessageSyncReq(const JsonObject &jsonObject,
    std::shared_ptr<DmAuthContext> context)
{
    if (jsonObject.IsDiscarded() || !jsonObject[TAG_SYNC].IsString()) {
        LOGE("json error");
        return ERR_DM_FAILED;
    }
    std::string enSyncMsg = jsonObject[TAG_SYNC].Get<std::string>();
    // Decrypt data and parse data into context
    int32_t ret = DecryptSyncMessage(context, context->accesser, enSyncMsg);
    if (ret != DM_OK) {
        LOGE("DecryptSyncMessage enSyncMsg error");
        return ret;
    }
    context->authStateMachine->TransitionTo(std::make_shared<AuthSinkDataSyncState>());
    return DM_OK;
}

// Parse 190 message save the remote encrypted quadruple, acl sp skid
int32_t DmAuthMessageProcessor::ParseMessageSyncResp(const JsonObject &jsonObject,
    std::shared_ptr<DmAuthContext> context)
{
    if (jsonObject.IsDiscarded() || !jsonObject[TAG_SYNC].IsString()) {
        LOGE("json error");
        return ERR_DM_FAILED;
    }
    std::string enSyncMsg = jsonObject[TAG_SYNC].Get<std::string>();
    // Decrypt data and parse data into context
    int32_t ret = DecryptSyncMessage(context, context->accessee, enSyncMsg);
    if (ret != DM_OK) {
        LOGE("DecryptSyncMessage enSyncMsg error");
        return ret;
    }
    context->authStateMachine->TransitionTo(std::make_shared<AuthSrcDataSyncState>());
    return DM_OK;
}

// Parse 200 message
int32_t DmAuthMessageProcessor::ParseMessageSinkFinish(const JsonObject &jsonObject,
    std::shared_ptr<DmAuthContext> context)
{
    if (jsonObject[TAG_REPLY].IsNumberInteger()) {
        context->reply = jsonObject[TAG_REPLY].Get<int32_t>();
    }
    if (jsonObject[TAG_REASON].IsNumberInteger()) {
        context->reason = jsonObject[TAG_REASON].Get<int32_t>();
    }

    /* In case of an exception, there may be a state waiting for an event.
    In the normal process, no state is waiting for events. */
    if (context->reason != DM_OK) {
        context->authStateMachine->NotifyEventFinish(DmEventType::ON_FAIL);
    }
    context->authStateMachine->TransitionTo(std::make_shared<AuthSinkFinishState>());
    return DM_OK;
}

// Parse 201 message
int32_t DmAuthMessageProcessor::ParseMessageSrcFinish(const JsonObject &jsonObject,
    std::shared_ptr<DmAuthContext> context)
{
    if (IsInt32(jsonObject, TAG_REPLY)) {
        context->reply = jsonObject[TAG_REPLY].Get<int32_t>();
    }
    if (IsInt32(jsonObject, TAG_REASON)) {
        context->reason = jsonObject[TAG_REASON].Get<int32_t>();
    }
    if (IsInt64(jsonObject, TAG_REMAINING_FROZEN_TIME)) {
        context->remainingFrozenTime = jsonObject[TAG_REMAINING_FROZEN_TIME].Get<int64_t>();
    }

    /* In case of an exception, there may be a state waiting for an event.
    In the normal process, no state is waiting for events. */
    if (context->reason != DM_OK) {
        context->authStateMachine->NotifyEventFinish(DmEventType::ON_FAIL);
    }
    context->authStateMachine->TransitionTo(std::make_shared<AuthSrcFinishState>());
    return DM_OK;
}

int32_t DmAuthMessageProcessor::CheckLogicalSessionId(const JsonObject &jsonObject,
    std::shared_ptr<DmAuthContext> context)
{
    if (jsonObject[DM_TAG_LOGICAL_SESSION_ID].IsNumberInteger()) {
        if (context->logicalSessionId != 0 &&
            jsonObject[DM_TAG_LOGICAL_SESSION_ID].Get<uint64_t>() != context->logicalSessionId) {
            return ERR_DM_PARSE_MESSAGE_FAILED;
        }
    }
    return DM_OK;
}
int32_t DmAuthMessageProcessor::ParseNegotiateMessage(
    const JsonObject &jsonObject, std::shared_ptr<DmAuthContext> context)
{
    if (jsonObject[DM_TAG_LOGICAL_SESSION_ID].IsNumberInteger()) {
        context->logicalSessionId = jsonObject[DM_TAG_LOGICAL_SESSION_ID].Get<uint64_t>();
        context->requestId = static_cast<int64_t>(context->logicalSessionId);
    }
    if (IsString(jsonObject, TAG_PEER_BUNDLE_NAME_V2)) {
        context->accessee.bundleName = jsonObject[TAG_PEER_BUNDLE_NAME_V2].Get<std::string>();
    }
    if (IsInt32(jsonObject, TAG_PEER_DISPLAY_ID)) {
        context->accessee.displayId = jsonObject[TAG_PEER_DISPLAY_ID].Get<int32_t>();
    }
    if (IsString(jsonObject, TAG_HOST_PKGLABEL)) {
        context->pkgLabel = jsonObject[TAG_HOST_PKGLABEL].Get<std::string>();
    }
    if (IsString(jsonObject, DM_BUSINESS_ID)) {
        context->businessId = jsonObject[DM_BUSINESS_ID].Get<std::string>();
    }
    if (IsBool(jsonObject, TAG_NCM_BIND_TARGET)) {
        context->ncmBindTarget = jsonObject[TAG_NCM_BIND_TARGET].Get<bool>();
    }
    ParseAccesserInfo(jsonObject, context);
    ParseUltrasonicSide(jsonObject, context);
    ParseServiceNego(jsonObject, context);
    ParseProxyNegotiateMessage(jsonObject, context);
    context->authStateMachine->TransitionTo(std::make_shared<AuthSinkNegotiateStateMachine>());
    return DM_OK;
}

void DmAuthMessageProcessor::ParseServiceNego(const JsonObject &jsonObject,
    std::shared_ptr<DmAuthContext> context)
{
    context->isServiceBind = false;
    if (IsBool(jsonObject, PARAM_KEY_IS_SERVICE_BIND)) {
        context->isServiceBind = jsonObject[PARAM_KEY_IS_SERVICE_BIND].Get<bool>();
    }
    if (!context->isServiceBind) {
        return;
    }
    if (IsInt64(jsonObject, TAG_SERVICE_ID)) {
        context->accessee.serviceId = jsonObject[TAG_SERVICE_ID].Get<int64_t>();
    }
    if (context->accessee.serviceId == 0 && jsonObject[TAG_SERVICE_CODE].IsString()) {
        context->accessee.serviceCode = jsonObject[TAG_SERVICE_CODE].Get<std::string>();
    }
}

void DmAuthMessageProcessor::ParseAccesserInfo(const JsonObject &jsonObject,
    std::shared_ptr<DmAuthContext> context)
{
    if (jsonObject[TAG_PKG_NAME].IsString()) {
        context->pkgName = jsonObject[TAG_PKG_NAME].Get<std::string>();
        context->accesser.pkgName = context->pkgName;
        context->accessee.pkgName = context->accesser.pkgName;
    }
    if (jsonObject[TAG_PEER_PKG_NAME].IsString()) {
        context->accessee.pkgName = jsonObject[TAG_PEER_PKG_NAME].Get<std::string>();
    }
    if (jsonObject[TAG_DM_VERSION_V2].IsString()) {
        context->accesser.dmVersion = jsonObject[TAG_DM_VERSION_V2].Get<std::string>();
    }
    if (jsonObject[TAG_USER_ID].IsNumberInteger()) {
        context->accesser.userId = jsonObject[TAG_USER_ID].Get<int32_t>();
    }
    if (jsonObject[TAG_DEVICE_ID_HASH].IsString()) {
        context->accesser.deviceIdHash = jsonObject[TAG_DEVICE_ID_HASH].Get<std::string>();
    }
    if (jsonObject[TAG_ACCOUNT_ID_HASH].IsString()) {
        context->accesser.accountIdHash = jsonObject[TAG_ACCOUNT_ID_HASH].Get<std::string>();
    }
    if (jsonObject[TAG_TOKEN_ID_HASH].IsString()) {
        context->accesser.tokenIdHash = jsonObject[TAG_TOKEN_ID_HASH].Get<std::string>();
    }
    if (jsonObject[TAG_BUNDLE_NAME_V2].IsString()) {
        context->accesser.bundleName = jsonObject[TAG_BUNDLE_NAME_V2].Get<std::string>();
    }
    if (jsonObject[TAG_EXTRA_INFO].IsString()) {
        context->accesser.extraInfo = jsonObject[TAG_EXTRA_INFO].Get<std::string>();
    }
    if (jsonObject[TAG_DEVICE_TYPE].IsNumberInteger()) {
        context->accesser.deviceType = jsonObject[TAG_DEVICE_TYPE].Get<int32_t>();
    }
    if (jsonObject[TAG_PEER_USER_ID].IsNumberInteger()) {
        context->accessee.userId = jsonObject[TAG_PEER_USER_ID].Get<int32_t>();
    }
}

void DmAuthMessageProcessor::ParseCert(const JsonObject &jsonObject,
    std::shared_ptr<DmAuthContext> context)
{
    if (jsonObject[TAG_DM_CERT_CHAIN].IsString()) {
        context->accesser.cert = jsonObject[TAG_DM_CERT_CHAIN].Get<std::string>();
    }
    if (jsonObject[TAG_IS_COMMON_FLAG].IsBoolean()) {
        context->accesser.isCommonFlag = jsonObject[TAG_IS_COMMON_FLAG].Get<bool>();
    }
}
// LCOV_EXCL_START
int32_t DmAuthMessageProcessor::ParseServiceNegotiateMessage(
    const JsonObject &jsonObject, std::shared_ptr<DmAuthContext> context)
{
    LOGI("inner1");
    if (!IsString(jsonObject, PARAM_KEY_SUBJECT_SERVICE_ONES)) {
        LOGI("inner2");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    std::string subjectProxyOnesStr = jsonObject[PARAM_KEY_SUBJECT_SERVICE_ONES].Get<std::string>();
    JsonObject allProxyObj;
    if (!allProxyObj.Parse(subjectProxyOnesStr) || allProxyObj.IsDiscarded()) {
        LOGE("subjectServiceOnes json parse failed.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    for (auto const &item : allProxyObj.Items()) {
        if (!IsString(item, TAG_PROXY_CONTEXT_ID) || !IsString(item, TAG_PKG_NAME) ||
            !IsInt64(item, TAG_SERVICE_ID) || !IsString(item, TAG_TOKEN_ID_HASH)) {
            continue;
        }
        DmProxyAuthContext proxyAuthContext;
        proxyAuthContext.proxyContextId = item[TAG_PROXY_CONTEXT_ID].Get<std::string>();
        proxyAuthContext.proxyAccesser.pkgName = item[TAG_PKG_NAME].Get<std::string>();
        proxyAuthContext.proxyAccessee.serviceId = item[TAG_SERVICE_ID].Get<int64_t>();
        proxyAuthContext.proxyAccesser.tokenIdHash = item[TAG_TOKEN_ID_HASH].Get<std::string>();
        if (IsString(item, TAG_HOST_PKGLABEL)) {
            proxyAuthContext.pkgLabel = item[TAG_HOST_PKGLABEL].Get<std::string>();
        }
        if (IsInt64(item, TAG_TOKEN_ID)) {
            proxyAuthContext.proxyAccesser.tokenId = item[TAG_TOKEN_ID].Get<int64_t>();
        }
        context->subjectServiceOnes.push_back(proxyAuthContext);
    }
    LOGI("inner3");
    return DM_OK;
}

// Parse proxyed subject items of the 80 message into the target list.
static void ParseProxyedSubjectItems(std::shared_ptr<DmAuthContext> context, const JsonObject &allProxyObj)
{
    for (auto const &item : allProxyObj.Items()) {
        if (!IsString(item, TAG_PROXY_CONTEXT_ID) || !IsString(item, TAG_BUNDLE_NAME) ||
            !IsString(item, TAG_PEER_BUNDLE_NAME) || !IsString(item, TAG_TOKEN_ID_HASH)) {
            continue;
        }
        DmProxyAuthContext proxyAuthContext;
        proxyAuthContext.proxyContextId = item[TAG_PROXY_CONTEXT_ID].Get<std::string>();
        proxyAuthContext.proxyAccesser.bundleName = item[TAG_BUNDLE_NAME].Get<std::string>();
        proxyAuthContext.proxyAccessee.bundleName = item[TAG_PEER_BUNDLE_NAME].Get<std::string>();
        proxyAuthContext.proxyAccesser.tokenIdHash = item[TAG_TOKEN_ID_HASH].Get<std::string>();
        if (IsString(item, TAG_HOST_PKGLABEL)) {
            proxyAuthContext.pkgLabel = item[TAG_HOST_PKGLABEL].Get<std::string>();
        }
        context->subjectProxyOnes.push_back(proxyAuthContext);
    }
}

int32_t DmAuthMessageProcessor::ParseProxyNegotiateMessage(
    const JsonObject &jsonObject, std::shared_ptr<DmAuthContext> context)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    context->IsProxyBind = false;
    //accesser dmVersion greater than DM_VERSION_5_1_1
    if (CompareVersion(context->accesser.dmVersion, DM_VERSION_5_1_1) && IsBool(jsonObject, PARAM_KEY_IS_PROXY_BIND)) {
        context->IsProxyBind = jsonObject[PARAM_KEY_IS_PROXY_BIND].Get<bool>();
    }
    if (!context->IsProxyBind) {
        return DM_OK;
    }
    if (IsInt32(jsonObject, TAG_AUTH_TYPE)) {
        context->authType = static_cast<DmAuthType>(jsonObject[TAG_AUTH_TYPE].Get<int32_t>());
    }
    if (IsBool(jsonObject, PARAM_KEY_IS_CALLING_PROXY_AS_SUBJECT)) {
        context->IsCallingProxyAsSubject = jsonObject[PARAM_KEY_IS_CALLING_PROXY_AS_SUBJECT].Get<bool>();
    }
    if (context->isServiceBind) {
        return ParseServiceNegotiateMessage(jsonObject, context);
    }

    if (!IsString(jsonObject, PARAM_KEY_SUBJECT_PROXYED_SUBJECTS)) {
        return ERR_DM_INPUT_PARA_INVALID;
    }
    std::string subjectProxyOnesStr = jsonObject[PARAM_KEY_SUBJECT_PROXYED_SUBJECTS].Get<std::string>();
    JsonObject allProxyObj;
    if (!allProxyObj.Parse(subjectProxyOnesStr) || allProxyObj.IsDiscarded()) {
        LOGE("subjectProxyOnes json parse failed.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    ParseProxyedSubjectItems(context, allProxyObj);
    return DM_OK;
}
// LCOV_EXCL_STOP
void DmAuthMessageProcessor::ParseUltrasonicSide(
    const JsonObject &jsonObject, std::shared_ptr<DmAuthContext> context)
{
    if (!jsonObject[TAG_ULTRASONIC_SIDE].IsNumberInteger()) {
        context->ultrasonicInfo = DmUltrasonicInfo::DM_Ultrasonic_Invalid;
        return;
    }
    int32_t tempInfo = jsonObject[TAG_ULTRASONIC_SIDE].Get<int32_t>();
    if (tempInfo == DM_ULTRASONIC_REVERSE) {
        context->ultrasonicInfo = DmUltrasonicInfo::DM_Ultrasonic_Reverse;
    } else if (tempInfo == DM_ULTRASONIC_FORWARD) {
        context->ultrasonicInfo = DmUltrasonicInfo::DM_Ultrasonic_Forward;
    } else {
        context->ultrasonicInfo = DmUltrasonicInfo::DM_Ultrasonic_Invalid;
        return;
    }
    bool isSupport = true;
    if (context->ultrasonicInfo == DM_Ultrasonic_Forward) {
#ifdef SUPPORT_MSDP
        isSupport = Msdp::SpatialAwarenessMgrClient::GetInstance().IsPinCodeAbilitySupport(
            Msdp::PinCodeMode::MODE_PIN_SEND_CODE);
#endif
    }
    if (context->ultrasonicInfo == DM_Ultrasonic_Reverse) {
#ifdef SUPPORT_MSDP
        isSupport = Msdp::SpatialAwarenessMgrClient::GetInstance().IsPinCodeAbilitySupport(
            Msdp::PinCodeMode::MODE_PIN_RECEIVE_CODE);
#endif
    }
    JsonObject json;
    json[TAG_IS_SUPPORT_ULTRASONIC] = isSupport;
    context->accessee.extraInfo = json.Dump();
}

// Parse accessee base info fields of the 90 message.
static void ParseAccesseeInfoFromResp(const JsonObject &jsonObject, DmAccess &accessee)
{
    if (jsonObject[TAG_DEVICE_VERSION].IsString()) {
        accessee.dmVersion = jsonObject[TAG_DEVICE_VERSION].Get<std::string>();
    }
    if (jsonObject[TAG_DEVICE_NAME].IsString()) {
        accessee.deviceName = jsonObject[TAG_DEVICE_NAME].Get<std::string>();
    }
    if (jsonObject[TAG_DEVICE_ID_HASH].IsString()) {
        accessee.deviceIdHash = jsonObject[TAG_DEVICE_ID_HASH].Get<std::string>();
    }
    if (jsonObject[TAG_USER_ID].IsNumberInteger()) {
        accessee.userId = jsonObject[TAG_USER_ID].Get<int32_t>();
    }
    if (jsonObject[TAG_ACCOUNT_ID_HASH].IsString()) {
        accessee.accountIdHash = jsonObject[TAG_ACCOUNT_ID_HASH].Get<std::string>();
    }
    if (jsonObject[TAG_TOKEN_ID_HASH].IsString()) {
        accessee.tokenIdHash = jsonObject[TAG_TOKEN_ID_HASH].Get<std::string>();
    }
    if (jsonObject[TAG_NETWORKID_ID].IsString()) {
        accessee.networkId = jsonObject[TAG_NETWORKID_ID].Get<std::string>();
    }
    if (jsonObject[TAG_ACL_TYPE_LIST].IsString()) {
        accessee.aclTypeList = jsonObject[TAG_ACL_TYPE_LIST].Get<std::string>();
    }
    if (jsonObject[TAG_CERT_TYPE_LIST].IsString()) {
        accessee.credTypeList = jsonObject[TAG_CERT_TYPE_LIST].Get<std::string>();
    }
    if (jsonObject[TAG_LANGUAGE].IsString()) {
        accessee.language = jsonObject[TAG_LANGUAGE].Get<std::string>();
    }
    if (jsonObject[TAG_EXTRA_INFO].IsString()) {
        accessee.extraInfo = jsonObject[TAG_EXTRA_INFO].Get<std::string>();
    }
    if (jsonObject[TAG_CERT_RANDOM].IsNumberInteger()) {
        accessee.certRandom = jsonObject[TAG_CERT_RANDOM].Get<uint64_t>();
    }
    if (jsonObject[TAG_DEVICE_TYPE].IsNumberInteger()) {
        accessee.deviceType = jsonObject[TAG_DEVICE_TYPE].Get<int32_t>();
    }
}

int32_t DmAuthMessageProcessor::ParseMessageRespAclNegotiate(const JsonObject &jsonObject,
    std::shared_ptr<DmAuthContext> context)
{
    ParseAccesseeInfoFromResp(jsonObject, context->accessee);
    if (jsonObject[TAG_IS_ONLINE].IsBoolean()) {
        context->isOnline = jsonObject[TAG_IS_ONLINE].Get<bool>();
    }
    ParseMessageProxyRespAclNegotiate(jsonObject, context);
    context->authStateMachine->TransitionTo(std::make_shared<AuthSrcConfirmState>());
    return DM_OK;
}

// Update proxy items parsed from the 90 message into the target list.
static void UpdateProxyAclNegotiateItems(std::vector<DmProxyAuthContext> &targetList, const JsonObject &allProxyObj)
{
    for (auto const &item : allProxyObj.Items()) {
        if (!IsString(item, TAG_PROXY_CONTEXT_ID) || !IsString(item, TAG_TOKEN_ID_HASH) ||
            !IsString(item, TAG_ACL_TYPE_LIST) || !IsString(item, TAG_CERT_TYPE_LIST) ||
            !IsString(item, TAG_BUNDLE_NAME)) {
            continue;
        }
        DmProxyAuthContext proxyAuthContext;
        proxyAuthContext.proxyContextId = item[TAG_PROXY_CONTEXT_ID].Get<std::string>();
        auto it = std::find(targetList.begin(), targetList.end(), proxyAuthContext);
        if (it == targetList.end()) {
            continue;
        }
        if (IsInt64(item, TAG_SERVICE_ID)) {
            it->proxyAccessee.serviceId = item[TAG_SERVICE_ID].Get<int64_t>();
        }
        it->proxyAccessee.tokenIdHash = item[TAG_TOKEN_ID_HASH].Get<std::string>();
        it->proxyAccessee.aclTypeList = item[TAG_ACL_TYPE_LIST].Get<std::string>();
        it->proxyAccessee.credTypeList = item[TAG_CERT_TYPE_LIST].Get<std::string>();
        it->proxyAccessee.bundleName = item[TAG_BUNDLE_NAME].Get<std::string>();
    }
}

int32_t DmAuthMessageProcessor::ParseMessageProxyRespAclNegotiate(const JsonObject &jsonObject,
    std::shared_ptr<DmAuthContext> context)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    if (jsonObject[TAG_SERVICE_ID].IsNumberInteger()) {
        context->accessee.serviceId = jsonObject[TAG_SERVICE_ID].Get<int64_t>();
        context->accesser.serviceId = context->accessee.serviceId;
    }
    auto &targetList = context->isServiceBind ? context->subjectServiceOnes : context->subjectProxyOnes;
    auto targetKey = context->isServiceBind ? PARAM_KEY_SUBJECT_SERVICE_ONES : PARAM_KEY_SUBJECT_PROXYED_SUBJECTS;
    //sink not support proxy
    if (!CompareVersion(context->accessee.dmVersion, DM_VERSION_5_1_1)) {
        context->IsProxyBind = false;
        LOGE("sink does not support proxy");
        return DM_OK;
    } else if (IsBool(jsonObject, PARAM_KEY_IS_PROXY_BIND)) {
        context->IsProxyBind = jsonObject[PARAM_KEY_IS_PROXY_BIND].Get<bool>();
    }
    if (!context->IsProxyBind) {
        return DM_OK;
    }
    if (!IsString(jsonObject, targetKey)) {
        return ERR_DM_INPUT_PARA_INVALID;
    }
    std::string subjectProxyOnesStr = jsonObject[targetKey].Get<std::string>();
    JsonObject allProxyObj;
    if (!allProxyObj.Parse(subjectProxyOnesStr) || allProxyObj.IsDiscarded()) {
        LOGE("subjectProxyOnes json parse failed.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    UpdateProxyAclNegotiateItems(targetList, allProxyObj);
    return DM_OK;
}

int32_t DmAuthMessageProcessor::ParseMessageReqUserConfirm(const JsonObject &json,
    std::shared_ptr<DmAuthContext> context)
{
    if (json[TAG_DEVICE_TYPE].IsNumberInteger()) {
        context->accesser.deviceType = json[TAG_DEVICE_TYPE].Get<int32_t>();
    }
    if (json[TAG_DEVICE_NAME].IsString()) {
        context->accesser.deviceName = json[TAG_DEVICE_NAME].Get<std::string>();
    }
    if (json[TAG_AUTH_TYPE].IsNumberInteger()) {
        context->authType = static_cast<DmAuthType>(json[TAG_AUTH_TYPE].Get<int32_t>());
    }
    if (json[TAG_ACL_TYPE_LIST].IsString()) {
        context->accesser.aclTypeList = json[TAG_ACL_TYPE_LIST].Get<std::string>();
    }
    if (json[TAG_CERT_TYPE_LIST].IsString()) {
        context->accesser.credTypeList = json[TAG_CERT_TYPE_LIST].Get<std::string>();
    }
    if (json[TAG_EXTRA_INFO].IsString()) {
        context->accesser.extraInfo = json[TAG_EXTRA_INFO].Get<std::string>();
    }
    if (IsString(json, TAG_CUSTOM_DESCRIPTION)) {
        context->customData = json[TAG_CUSTOM_DESCRIPTION].Get<std::string>();
    }
    ParseMessageProxyReqUserConfirm(json, context);
    context->authStateMachine->TransitionTo(std::make_shared<AuthSinkConfirmState>());
    return DM_OK;
}
int32_t DmAuthMessageProcessor::ParseMessageProxyReqUserConfirm(const JsonObject &json,
    std::shared_ptr<DmAuthContext> context)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    if (!context->IsProxyBind) {
        return DM_OK;
    }
    auto &targetList = context->isServiceBind ? context->subjectServiceOnes : context->subjectProxyOnes;
    auto targetKey = context->isServiceBind ? PARAM_KEY_SUBJECT_SERVICE_ONES : PARAM_KEY_SUBJECT_PROXYED_SUBJECTS;
    if (!IsString(json, targetKey)) {
        return ERR_DM_INPUT_PARA_INVALID;
    }
    std::string subjectProxyOnesStr = json[targetKey].Get<std::string>();
    JsonObject allProxyObj;
    if (!allProxyObj.Parse(subjectProxyOnesStr) || allProxyObj.IsDiscarded()) {
        LOGE("subjectProxyOnes json parse failed.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    for (auto const &item : allProxyObj.Items()) {
        if (!IsString(item, TAG_PROXY_CONTEXT_ID) || !IsString(item, TAG_ACL_TYPE_LIST) ||
            !IsString(item, TAG_CERT_TYPE_LIST)) {
            continue;
        }
        DmProxyAuthContext proxyAuthContext;
        proxyAuthContext.proxyContextId = item[TAG_PROXY_CONTEXT_ID].Get<std::string>();
        auto it = std::find(targetList.begin(), targetList.end(), proxyAuthContext);
        if (it != targetList.end()) {
            it->proxyAccesser.aclTypeList = item[TAG_ACL_TYPE_LIST].Get<std::string>();
            it->proxyAccesser.credTypeList = item[TAG_CERT_TYPE_LIST].Get<std::string>();
        }
    }
    return DM_OK;
}

int32_t DmAuthMessageProcessor::ParseMessageRespUserConfirm(const JsonObject &json,
    std::shared_ptr<DmAuthContext> context)
{
    if (json[TAG_AUTH_TYPE_LIST].IsString()) {
        auto strList = json[TAG_AUTH_TYPE_LIST].Get<std::string>();
        context->authTypeList = stringToVectorAuthType(strList);
    }
    if (json[TAG_EXTRA_INFO].IsString()) {
        context->accessee.extraInfo = json[TAG_EXTRA_INFO].Get<std::string>();
    }
    ParseMessageProxyRespUserConfirm(json, context);
    context->authStateMachine->TransitionTo(std::make_shared<AuthSrcPinNegotiateStartState>());
    return DM_OK;
}
int32_t DmAuthMessageProcessor::ParseMessageProxyRespUserConfirm(const JsonObject &json,
    std::shared_ptr<DmAuthContext> context)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    if (!context->IsProxyBind) {
        return DM_OK;
    }
    auto &targetList = context->isServiceBind ? context->subjectServiceOnes : context->subjectProxyOnes;
    auto targetKey = context->isServiceBind ? PARAM_KEY_SUBJECT_SERVICE_ONES : PARAM_KEY_SUBJECT_PROXYED_SUBJECTS;
    if (!IsString(json, targetKey)) {
        targetList.clear();
        return ERR_DM_INPUT_PARA_INVALID;
    }
    std::string subjectProxyOnesStr = json[targetKey].Get<std::string>();
    JsonObject allProxyObj;
    allProxyObj.Parse(subjectProxyOnesStr);
    if (allProxyObj.IsDiscarded()) {
        targetList.clear();
        return ERR_DM_INPUT_PARA_INVALID;
    }
    std::vector<DmProxyAuthContext> sinksubjectProxyOnes;
    for (auto const &item : allProxyObj.Items()) {
        if (!IsString(item, TAG_PROXY_CONTEXT_ID)) {
            continue;
        }
        DmProxyAuthContext proxyAuthContext;
        proxyAuthContext.proxyContextId = item[TAG_PROXY_CONTEXT_ID].Get<std::string>();
        sinksubjectProxyOnes.push_back(proxyAuthContext);
    }
    for (auto item = targetList.begin(); item != targetList.end();) {
        if (std::find(sinksubjectProxyOnes.begin(), sinksubjectProxyOnes.end(), *item) != sinksubjectProxyOnes.end()) {
            item++;
        } else {
            item = targetList.erase(item);
        }
    }
    return DM_OK;
}

int32_t DmAuthMessageProcessor::ParseMessageReqPinAuthStart(const JsonObject &json,
    std::shared_ptr<DmAuthContext> context)
{
    if (json[TAG_DATA].IsString()) {
        context->transmitData = json[TAG_DATA].Get<std::string>();
    }
    if (context->authType == AUTH_TYPE_PIN_ULTRASONIC && context->ultrasonicInfo == DM_Ultrasonic_Reverse) {
        context->authStateMachine->TransitionTo(std::make_shared<AuthSinkReverseUltrasonicDoneState>());
    } else if (context->authType == AUTH_TYPE_PIN_ULTRASONIC && context->ultrasonicInfo == DM_Ultrasonic_Forward) {
        context->authStateMachine->TransitionTo(std::make_shared<AuthSinkForwardUltrasonicDoneState>());
    } else {
        context->authStateMachine->TransitionTo(std::make_shared<AuthSinkPinAuthStartState>());
    }
    return DM_OK;
}

int32_t DmAuthMessageProcessor::ParseMessageRespPinAuthStart(const JsonObject &json,
    std::shared_ptr<DmAuthContext> context)
{
    if (json[TAG_DATA].IsString()) {
        context->transmitData = json[TAG_DATA].Get<std::string>();
    }
    context->authStateMachine->TransitionTo(std::make_shared<AuthSrcPinAuthMsgNegotiateState>());
    return DM_OK;
}

int32_t DmAuthMessageProcessor::ParseMessageReqPinAuthNegotiate(const JsonObject &json,
    std::shared_ptr<DmAuthContext> context)
{
    if (json[TAG_DATA].IsString()) {
        context->transmitData = json[TAG_DATA].Get<std::string>();
    }
    context->authStateMachine->TransitionTo(std::make_shared<AuthSinkPinAuthMsgNegotiateState>());
    return DM_OK;
}

int32_t DmAuthMessageProcessor::ParseMessageReverseUltrasonicStart(const JsonObject &json,
    std::shared_ptr<DmAuthContext> context)
{
    context->authStateMachine->TransitionTo(std::make_shared<AuthSinkReverseUltrasonicStartState>());
    return DM_OK;
}

int32_t DmAuthMessageProcessor::ParseMessageReverseUltrasonicDone(const JsonObject &json,
    std::shared_ptr<DmAuthContext> context)
{
    if (json[TAG_REPLY].IsNumberInteger()) {
        context->reply = json[TAG_REPLY].Get<int32_t>();
    }
    if (context->reply == DM_OK) {
        context->authStateMachine->TransitionTo(std::make_shared<AuthSrcReverseUltrasonicDoneState>());
    }
    return DM_OK;
}

int32_t DmAuthMessageProcessor::ParseMessageForwardUltrasonicStart(const JsonObject &json,
    std::shared_ptr<DmAuthContext> context)
{
    context->authStateMachine->TransitionTo(std::make_shared<AuthSinkForwardUltrasonicStartState>());
    return DM_OK;
}

int32_t DmAuthMessageProcessor::ParseMessageForwardUltrasonicNegotiate(const JsonObject &json,
    std::shared_ptr<DmAuthContext> context)
{
    context->authStateMachine->TransitionTo(std::make_shared<AuthSrcForwardUltrasonicDoneState>());
    return DM_OK;
}

} // namespace DistributedHardware
} // namespace OHOS
