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

#include <zlib.h>
#include <sstream>

#include <mbedtls/base64.h>
#include "parameter.h"

#include "access_control_profile.h"
#include "distributed_device_profile_client.h"

#include "deviceprofile_connector.h"
#include "dm_log.h"
#include "dm_constants.h"
#include "dm_anonymous.h"
#include "dm_auth_manager_base.h"
#include "dm_auth_context.h"
#include "dm_auth_state_machine.h"

namespace OHOS {
namespace DistributedHardware {

// Json keys and limits used by this file only and not declared in any public header.
constexpr uint32_t MAX_MESSAGE_LENGTH = 64 * 1024 * 1024;
constexpr const char* TAG_CUSTOM_DESCRIPTION = "CUSTOMDESC";
constexpr const char* TAG_ACL_TYPE_LIST = "aclTypeList";
constexpr const char* TAG_CERT_TYPE_LIST = "certTypeList";
constexpr const char* TAG_SERVICE_INFOS = "serviceInfos";
constexpr const char* TAG_DEVICE_TYPE = "DEVICETYPE";
constexpr const char* TAG_PROXY_SERVICE_ID = "proxyServiceId";
constexpr const char* TAG_PKG_NAME = "pkgName";
constexpr const char* TAG_NCM_BIND_TARGET = "ncm_bind_target";
constexpr const char* TAG_SRC_SUBJECT_PKGNAME = "srcSubjectPkgname";
constexpr const char* TAG_SUBJECT_SERVICEID = "subjectServiceId";
constexpr const char* TAG_ACCESSEE_SERVICE_INFO = "accesseeServiceInfo";
constexpr const char* SERVICEINFO_USER_ID = "userId";
constexpr const char* SERVICEINFO_SERVICE_ID = "serviceId";
constexpr const char* SERVICEINFO_DISPLAY_ID = "displayId";
constexpr const char* SERVICEINFO_PUBLISH_STATE = "publishState";
constexpr const char* SERVICEINFO_DEVICE_ID = "deviceId";
constexpr const char* SERVICEINFO_NETWORK_ID = "networkId";
constexpr const char* SERVICEINFO_SERVICE_OWNER_TOKEN_ID = "serviceOwnerTokenId";
constexpr const char* SERVICEINFO_SERVICE_OWNER_PKG_NAME = "serviceOwnerPkgName";
constexpr const char* SERVICEINFO_SERVICE_REGISTER_TOKEN_ID = "serviceRegisterTokenId";
constexpr const char* SERVICEINFO_SERVICE_TYPE = "serviceType";
constexpr const char* SERVICEINFO_SERVICE_NAME = "serviceName";
constexpr const char* SERVICEINFO_SERVICE_DISPLAY_NAME = "serviceDisplayName";
constexpr const char* SERVICEINFO_SERVICE_CODE = "serviceCode";
constexpr const char* SERVICEINFO_CUSTOM_DATA = "customData";
constexpr const char* SERVICEINFO_DATA_LEN = "dataLen";
constexpr const char* SERVICEINFO_TIME_STAMP = "timeStamp";
constexpr const char* SERVICEINFO_VERSION = "version";
constexpr const char* SERVICEINFO_EXTRA_DATA = "extraData";
constexpr const char* SERVICEINFO_DESCRIPTION = "description";

static void SaveToDmAccessSync(DmAccessToSync &accessToSync, const std::shared_ptr<DmAuthContext> context,
    const DmAccess &accessSide)
{
    accessToSync.deviceName = accessSide.deviceName;
    accessToSync.deviceNameFull = context->softbusConnector->GetLocalDeviceName();
    accessToSync.deviceId = accessSide.deviceId;
    accessToSync.userId = accessSide.userId;
    accessToSync.accountId = accessSide.accountId;
    accessToSync.tokenId = accessSide.tokenId;
    accessToSync.bundleName = accessSide.bundleName;
    accessToSync.pkgName = accessSide.pkgName;
    accessToSync.bindLevel = accessSide.bindLevel;
}

static bool GetPinMatchFlag(const std::string &pkgName, DmAuthType authType)
{
    DistributedDeviceProfile::LocalServiceInfo srvInfo;
    int32_t dpRet = DeviceProfileConnector::GetInstance().GetLocalServiceInfoByBundleNameAndPinExchangeType(
        pkgName, static_cast<int32_t>(authType), srvInfo);
    if (dpRet != DM_OK) {
        LOGE("GetLocalServiceInfoByBundleNameAndPinExchangeType failed, pkgName=%{public}s, ret=%{public}d",
            pkgName.c_str(), dpRet);
        return false;
    }
    std::string extra = srvInfo.GetExtraInfo();
    if (extra.empty()) {
        LOGE("extra.empty()");
        return false;
    }
    JsonObject extraObj;
    extraObj.Parse(extra);
    if (extraObj.IsDiscarded()) {
        LOGE("extraObj.IsDiscarded()");
        return false;
    }
    bool flag = false;
    if (IsBool(extraObj, PIN_MATCH_FLAG)) {
        flag = extraObj[PIN_MATCH_FLAG].Get<bool>();
        return flag;
    }
    return false;
}

static std::string vectorAuthTypeToString(const std::vector<DmAuthType> &vec)
{
    std::ostringstream oss;
    for (size_t i = 0; i < vec.size(); ++i) {
        oss << static_cast<int32_t>(vec[i]);
        if (i != vec.size() - 1) {
            oss << " ";  // Add a separator (e.g. space)
        }
    }
    return oss.str();
}

// Check whether the token already exists in the proxy array of the extra data.
static bool IsTokenInProxyJson(const JsonObject &proxyObj, int64_t tokenId)
{
    if (proxyObj.IsDiscarded()) {
        return false;
    }
    for (auto const &item : proxyObj.Items()) {
        if (item.IsDiscarded() || !item.IsNumberInteger()) {
            continue;
        }
        if (tokenId == item.Get<int64_t>()) {
            return true;
        }
    }
    return false;
}

// Fill the acl checksum of the sync message, return ERR_DM_FAILED when query fails.
// Named with the g_ prefix to satisfy the G.NAM.03 naming rule for file-scope symbols.
static int32_t g_fillAclCheckSum(std::shared_ptr<DmAuthContext> &context, JsonObject &syncMsgJson)
{
    char localDeviceId[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localDeviceId, DEVICE_UUID_LENGTH);
    std::string localUdid = static_cast<std::string>(localDeviceId);
    DmAccess &access = (context->accesser.deviceId == localUdid) ? context->accesser : context->accessee;
    DmAccess &remoteAccess = (context->accesser.deviceId == localUdid) ? context->accessee : context->accesser;
    std::string aclHashList;
    int32_t ret = DeviceProfileConnector::GetInstance().GetAclListHashStr({localUdid, access.userId},
        {remoteAccess.deviceId, remoteAccess.userId}, aclHashList, DM_ACL_AGING_VERSION);
    if (ret != DM_OK) {
        LOGE("GetAclListHashStr failed");
        return ERR_DM_FAILED;
    }
    syncMsgJson[TAG_ACL_CHECKSUM] = aclHashList;
    return DM_OK;
}

// Fill the pin match flag for import auth code compatibility.
static void FillImportAuthCodeFlag(std::shared_ptr<DmAuthContext> &context, JsonObject &syncMsgJson)
{
    if (!DmAuthState::IsImportAuthCodeCompatibility(context->authType)) {
        return;
    }
    std::string queryPkgName;
    if (context->direction == DM_AUTH_SOURCE) {
        queryPkgName = context->accesser.pkgName;
    } else {
        queryPkgName = context->accessee.pkgName;
    }
    context->pinCodeFlag = GetPinMatchFlag(queryPkgName, context->authType);
    syncMsgJson[PIN_MATCH_FLAG] = context->pinCodeFlag;
    syncMsgJson[TAG_NCM_BIND_TARGET] = context->ncmBindTarget;
}

// Fill one service info item into the sync message json array.
static void FillServiceInfoItem(JsonObject &object, const DistributedDeviceProfile::ServiceInfo &info)
{
    object[SERVICEINFO_USER_ID] = info.GetUserId();
    object[SERVICEINFO_SERVICE_ID] = info.GetServiceId();
    object[SERVICEINFO_DISPLAY_ID] = info.GetDisplayId();
    object[SERVICEINFO_PUBLISH_STATE] = info.GetPublishState();
    object[SERVICEINFO_DEVICE_ID] = info.GetUdid();
    object[SERVICEINFO_SERVICE_OWNER_TOKEN_ID] = info.GetServiceOwnerTokenId();
    object[SERVICEINFO_SERVICE_OWNER_PKG_NAME] = info.GetServiceOwnerPkgName();
    object[SERVICEINFO_SERVICE_REGISTER_TOKEN_ID] = info.GetServiceRegisterTokenId();
    object[SERVICEINFO_SERVICE_TYPE] = info.GetServiceType();
    object[SERVICEINFO_SERVICE_NAME] = info.GetServiceName();
    object[SERVICEINFO_SERVICE_DISPLAY_NAME] = info.GetServiceDisplayName();
    object[SERVICEINFO_SERVICE_CODE] = info.GetServiceCode();
    object[SERVICEINFO_CUSTOM_DATA] = info.GetCustomData();
    object[SERVICEINFO_DATA_LEN] = info.GetDataLen();
    object[SERVICEINFO_TIME_STAMP] = info.GetTimeStamp();
    object[SERVICEINFO_VERSION] = info.GetVersion();
    object[SERVICEINFO_EXTRA_DATA] = info.GetExtraData();
    object[SERVICEINFO_DESCRIPTION] = info.GetDescription();
}

// Merge the token into the accesser extra data of the acl profile.
static bool MergeProxyTokenToAccesser(DistributedDeviceProfile::AccessControlProfile &profile, int64_t tokenId)
{
    JsonObject accesserExtObj;
    if (!profile.GetAccesser().GetAccesserExtraData().empty()) {
        accesserExtObj.Parse(profile.GetAccesser().GetAccesserExtraData());
    }
    JsonObject accesserProxyObj(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
    if (IsString(accesserExtObj, TAG_PROXY)) {
        std::string proxyStr = accesserExtObj[TAG_PROXY].Get<std::string>();
        accesserProxyObj.Parse(proxyStr);
    }
    if (IsTokenInProxyJson(accesserProxyObj, tokenId)) {
        return false;
    }
    accesserProxyObj.PushBack(tokenId);
    accesserExtObj[TAG_PROXY] = accesserProxyObj.Dump();
    DistributedDeviceProfile::Accesser accesser = profile.GetAccesser();
    accesser.SetAccesserExtraData(accesserExtObj.Dump());
    profile.SetAccesser(accesser);
    return true;
}

// Merge the token into the accessee extra data of the acl profile.
static bool MergeProxyTokenToAccessee(DistributedDeviceProfile::AccessControlProfile &profile, int64_t tokenId)
{
    JsonObject accesseeExtObj;
    if (!profile.GetAccessee().GetAccesseeExtraData().empty()) {
        accesseeExtObj.Parse(profile.GetAccessee().GetAccesseeExtraData());
    }
    JsonObject accesseeProxyObj(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
    if (IsString(accesseeExtObj, TAG_PROXY)) {
        std::string proxyStr = accesseeExtObj[TAG_PROXY].Get<std::string>();
        accesseeProxyObj.Parse(proxyStr);
    }
    if (IsTokenInProxyJson(accesseeProxyObj, tokenId)) {
        return false;
    }
    accesseeProxyObj.PushBack(tokenId);
    accesseeExtObj[TAG_PROXY] = accesseeProxyObj.Dump();
    DistributedDeviceProfile::Accessee accessee = profile.GetAccessee();
    accessee.SetAccesseeExtraData(accesseeExtObj.Dump());
    profile.SetAccessee(accessee);
    return true;
}

int32_t DmAuthMessageProcessor::DecryptSyncMessage(std::shared_ptr<DmAuthContext> &context,
    DmAccess &access, std::string &enSyncMsg)
{
    CHECK_NULL_RETURN(cryptoMgr_, ERR_DM_POINT_NULL);
    std::string syncMsgCompress = "";
    int32_t ret = cryptoMgr_->DecryptMessage(enSyncMsg, syncMsgCompress);
    if (ret != DM_OK) {
        LOGE("syncMsg error");
        return ret;
    }
    JsonObject plainJson(syncMsgCompress);
    if (plainJson.IsDiscarded()) {
        LOGE("plainJson error");
        return ERR_DM_FAILED;
    }
    if (!plainJson[TAG_COMPRESS_ORI_LEN].IsNumberInteger()) {
        LOGE("TAG_COMPRESS_ORI_LEN json error");
        return ERR_DM_FAILED;
    }
    int32_t dataLen = plainJson[TAG_COMPRESS_ORI_LEN].Get<int32_t>();
    if (!plainJson[TAG_COMPRESS].IsString()) {
        LOGE("TAG_COMPRESS_ORI_LEN json error");
        return ERR_DM_FAILED;
    }
    std::string compressMsg = plainJson[TAG_COMPRESS].Get<std::string>();
    std::string compressBase64 = Base64Decode(compressMsg);
    std::string syncMsg = DecompressSyncMsg(compressBase64, dataLen);
    JsonObject jsonObject(syncMsg);
    if (jsonObject.IsDiscarded()) {
        LOGE("jsonStr error");
        return ERR_DM_FAILED;
    }

    ret = ParseSyncMessage(context, access, jsonObject);
    if (ret != DM_OK) {
        LOGE("ParseSyncMessage jsonStr error");
        return ret;
    }
    return DM_OK;
}

int32_t DmAuthMessageProcessor::CreateMessageReqUserConfirm(std::shared_ptr<DmAuthContext> context, JsonObject &json)
{
    json[TAG_AUTH_TYPE] = context->authType;
    json[TAG_ACL_TYPE_LIST] = context->accesser.aclTypeList;
    json[TAG_CERT_TYPE_LIST] = context->accesser.credTypeList;
    json[TAG_DEVICE_TYPE] = context->accesser.deviceType;
    json[TAG_DEVICE_NAME] = context->accesser.deviceName;
    json[TAG_EXTRA_INFO] = context->accesser.extraInfo;
    json[TAG_CUSTOM_DESCRIPTION] = context->customData;
    CreateMessageProxyReqUserConfirm(context, json);
    return DM_OK;
}
int32_t DmAuthMessageProcessor::CreateMessageProxyReqUserConfirm(std::shared_ptr<DmAuthContext> context,
    JsonObject &json)
{
    auto &targetList = context->isServiceBind ? context->subjectServiceOnes : context->subjectProxyOnes;
    auto targetKey = context->isServiceBind ? PARAM_KEY_SUBJECT_SERVICE_ONES : PARAM_KEY_SUBJECT_PROXYED_SUBJECTS;
    if (context != nullptr && context->IsProxyBind && !targetList.empty()) {
        JsonObject allProxyObj(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
        for (const auto &app : targetList) {
            JsonObject object;
            object[TAG_PROXY_CONTEXT_ID] = app.proxyContextId;
            object[TAG_ACL_TYPE_LIST] = app.proxyAccesser.aclTypeList;
            object[TAG_CERT_TYPE_LIST] = app.proxyAccesser.credTypeList;
            allProxyObj.PushBack(object);
        }
        json[targetKey] = allProxyObj.Dump();
    }
    return DM_OK;
}
int32_t DmAuthMessageProcessor::CreateMessageRespUserConfirm(std::shared_ptr<DmAuthContext> context, JsonObject &json)
{
    CHECK_NULL_RETURN(context, ERR_DM_FAILED);
    auto &targetList = context->isServiceBind ? context->subjectServiceOnes : context->subjectProxyOnes;
    auto targetKey = context->isServiceBind ? PARAM_KEY_SUBJECT_SERVICE_ONES : PARAM_KEY_SUBJECT_PROXYED_SUBJECTS;
    json[TAG_AUTH_TYPE_LIST] = vectorAuthTypeToString(context->authTypeList);
    json[TAG_EXTRA_INFO] = context->accessee.extraInfo;
    if (context->IsProxyBind && !targetList.empty()) {
        JsonObject allProxyObj(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
        for (const auto &app : targetList) {
            JsonObject object;
            object[TAG_PROXY_CONTEXT_ID] = app.proxyContextId;
            allProxyObj.PushBack(object);
        }
        json[targetKey] = allProxyObj.Dump();
    }
    return DM_OK;
}

int32_t DmAuthMessageProcessor::CreateMessageReqPinAuthStart(std::shared_ptr<DmAuthContext> context, JsonObject &json)
{
    json[TAG_DATA] = context->transmitData;
    return DM_OK;
}

int32_t DmAuthMessageProcessor::CreateMessageRespPinAuthStart(std::shared_ptr<DmAuthContext> context, JsonObject &json)
{
    json[TAG_DATA] = context->transmitData;
    return DM_OK;
}

int32_t DmAuthMessageProcessor::CreateMessageReqPinAuthNegotiate(std::shared_ptr<DmAuthContext> context,
    JsonObject &json)
{
    json[TAG_DATA] = context->transmitData;
    return DM_OK;
}

int32_t DmAuthMessageProcessor::CreateMessageRespPinAuthNegotiate(std::shared_ptr<DmAuthContext> context,
    JsonObject &json)
{
    json[TAG_DATA] = context->transmitData;
    return DM_OK;
}

int32_t DmAuthMessageProcessor::CreateMessageReverseUltrasonicStart(std::shared_ptr<DmAuthContext> context,
    JsonObject &json)
{
    json[TAG_REPLY] = context->reply;
    return DM_OK;
}

int32_t DmAuthMessageProcessor::CreateMessageReverseUltrasonicDone(std::shared_ptr<DmAuthContext> context,
    JsonObject &json)
{
    json[TAG_REPLY] = context->reply;
    return DM_OK;
}

int32_t DmAuthMessageProcessor::CreateMessageForwardUltrasonicStart(std::shared_ptr<DmAuthContext> context,
    JsonObject &json)
{
    json[TAG_REPLY] = context->reply;
    return DM_OK;
}

int32_t DmAuthMessageProcessor::CreateMessageForwardUltrasonicNegotiate(std::shared_ptr<DmAuthContext> context,
    JsonObject &json)
{
    json[TAG_REPLY] = context->reply;
    return DM_OK;
}

void DmAuthMessageProcessor::CreateAndSendMsg(DmMessageType msgType, std::shared_ptr<DmAuthContext> context)
{
    CHECK_NULL_VOID(context);
    auto message = CreateMessage(msgType, context);
    int32_t ret = context->softbusConnector->GetSoftbusSession()->SendData(context->sessionId, message);
    if (ret != DM_OK) {
        if (context->direction == DM_AUTH_SOURCE) {
            context->authStateMachine->TransitionTo(std::make_shared<AuthSrcFinishState>());
        } else {
            context->authStateMachine->TransitionTo(std::make_shared<AuthSinkFinishState>());
        }
    }
}

std::string DmAuthMessageProcessor::CompressSyncMsg(std::string &inputStr)
{
    uint32_t srcLen = inputStr.size();
    uint32_t boundSize = compressBound(srcLen);  // Maximum compression length
    if (boundSize == 0) {
        LOGE("zlib compressBound failed");
        return "";
    }
    std::string compressed(boundSize, '\0');

    // Compress to reserved space
    unsigned long destSize = boundSize;  // Actual usable length
    int32_t ret = compress(reinterpret_cast<Bytef *>(&compressed[0]), &destSize,
                           reinterpret_cast<const Bytef *>(inputStr.data()), srcLen);
    if (ret != Z_OK) {
        LOGE("zlib compress failed");
        return "";
    }
    compressed.resize(destSize); // Actual usage length
    return compressed;
}

std::string DmAuthMessageProcessor::DecompressSyncMsg(std::string& compressed, uint32_t oriLen)
{
    if (oriLen == 0 || oriLen >= MAX_MESSAGE_LENGTH) {
        LOGE("decompress oriLen param error");
        return "";
    }
    std::string decompressed;
    decompressed.resize(oriLen);
    unsigned long destLen = oriLen; // Actual usage length
    int32_t ret = uncompress(reinterpret_cast<Bytef *>(&decompressed[0]), &destLen,
                             reinterpret_cast<const Bytef *>(compressed.data()),  // Skip header when decompressing
                             compressed.size());
    if (ret != Z_OK || destLen != oriLen) {
        LOGE("decompress failed");
        return "";
    }
    return decompressed;
}

std::string DmAuthMessageProcessor::Base64Encode(std::string &inputStr)
{
    // Convert input string to binary
    const unsigned char* src = reinterpret_cast<const unsigned char*>(inputStr.data());
    size_t srcLen = inputStr.size();
    if (srcLen >= MAX_MESSAGE_LENGTH) {
        LOGE("inputStr too long");
        return "";
    }
    // Calculate the maximum length after base64 encoding
    size_t maxEncodeLen = ((srcLen + 2) / 3) * 4 + 1;
    std::vector<unsigned char> buffer(maxEncodeLen);

    // Actual encoding length
    size_t encodedLen = 0;
    int32_t ret = mbedtls_base64_encode(buffer.data(), buffer.size(), &encodedLen, src, srcLen);
    if (ret != 0) {
        LOGE("mbedtls_base64_encode failed");
        return "";
    }
    return std::string(reinterpret_cast<const char*>(buffer.data()), encodedLen); // No terminator needed
}

std::string DmAuthMessageProcessor::Base64Decode(std::string &inputStr)
{
    // Convert input string to binary
    const unsigned char* src = reinterpret_cast<const unsigned char*>(inputStr.data());
    size_t srcLen = inputStr.size();
    if (srcLen >= MAX_MESSAGE_LENGTH) {
        LOGE("inputStr too long");
        return "";
    }
    // Calculate the maximum length after base64 encoding
    size_t maxEncodeLen = (srcLen / 4) *  3 + 1;
    std::vector<unsigned char> buffer(maxEncodeLen);

    // Actual encoding length
    size_t decodedLen = 0;
    int32_t ret = mbedtls_base64_decode(buffer.data(), buffer.size(), &decodedLen, src, srcLen);
    if (ret != 0) {
        LOGE("mbedtls_base64_decode failed");
        return "";
    }
    return std::string(reinterpret_cast<const char*>(buffer.data()), decodedLen); // No terminator needed
}

int32_t DmAuthMessageProcessor::EncryptSyncMessage(std::shared_ptr<DmAuthContext> &context, DmAccess &accessSide,
                                                   std::string &encSyncMsg)
{
    CHECK_NULL_RETURN(cryptoMgr_, ERR_DM_POINT_NULL);
    JsonObject syncMsgJson;
    DmAccessToSync accessToSync;
    SaveToDmAccessSync(accessToSync, context, accessSide);

    if (SetSyncMsgJson(context, accessSide, accessToSync, syncMsgJson) != DM_OK) {
        LOGE("SetSyncMsgJson failed");
        return ERR_DM_FAILED;
    }

    CreateProxyAccessMessage(context, syncMsgJson);
    std::string syncMsg = syncMsgJson.Dump();
    std::string compressMsg = CompressSyncMsg(syncMsg);
    if (compressMsg.empty()) {
        LOGE("compress failed");
        return ERR_DM_FAILED;
    }
    JsonObject plainJson;
    plainJson[TAG_COMPRESS_ORI_LEN] = syncMsg.size();
    plainJson[TAG_COMPRESS] = Base64Encode(compressMsg);
    return cryptoMgr_->EncryptMessage(plainJson.Dump(), encSyncMsg);
}
int32_t DmAuthMessageProcessor::SetSyncMsgJson(std::shared_ptr<DmAuthContext> &context,
    const DmAccess &accessSide, const DmAccessToSync &accessToSync, JsonObject &syncMsgJson)
{
    syncMsgJson[TAG_TRANSMIT_SK_ID] = std::to_string(accessSide.transmitSessionKeyId);
    syncMsgJson[TAG_TRANSMIT_SK_TIMESTAMP] = accessSide.transmitSkTimeStamp;
    syncMsgJson[TAG_TRANSMIT_CREDENTIAL_ID] = accessSide.transmitCredentialId;
    // First certification
    if (accessSide.isGenerateLnnCredential && accessSide.bindLevel != static_cast<int32_t>(USER)) {
        syncMsgJson[TAG_LNN_SK_ID] = std::to_string(accessSide.lnnSessionKeyId);
        syncMsgJson[TAG_LNN_SK_TIMESTAMP] = accessSide.lnnSkTimeStamp;
        syncMsgJson[TAG_LNN_CREDENTIAL_ID] = accessSide.lnnCredentialId;
    }
    JsonObject accessJsonObj{};
    accessJsonObj = accessToSync;
    syncMsgJson[TAG_DMVERSION] = accessSide.dmVersion;
    syncMsgJson[TAG_ACCESS] = accessJsonObj.Dump();
    syncMsgJson[TAG_PROXY] = ""; // Reserved field, leave blank
    syncMsgJson[TAG_PROXY_SERVICE_ID] = context->accessee.serviceId;
    if (g_fillAclCheckSum(context, syncMsgJson) != DM_OK) {
        return ERR_DM_FAILED;
    }
    if (context->direction == DmAuthDirection::DM_AUTH_SINK) {
        LOGI("Sink Send user confirm opt");
        syncMsgJson[TAG_USER_CONFIRM_OPT] = context->confirmOperation;
    }
    syncMsgJson[TAG_IS_COMMON_FLAG] = context->accesser.isCommonFlag;
    syncMsgJson[TAG_DM_CERT_CHAIN] = context->accesser.cert;
    FillImportAuthCodeFlag(context, syncMsgJson);
    if (context->isServiceBind) {
        GetAccesseeServiceInfo(syncMsgJson, context->serviceInfos, context->serviceId);
    }
    return DM_OK;
}

//LCOV_EXCL_START
void DmAuthMessageProcessor::GetAccesseeServiceInfo(JsonObject &syncMsgJson,
    std::vector<DistributedDeviceProfile::ServiceInfo> serviceInfos, std::vector<int64_t> serviceId)
{
    if (serviceInfos.empty()) {
        LOGI("Service info is empty");
        return;
    }
    JsonObject allProxyObj(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
    for (const auto &info : serviceInfos) {
        LOGI("inner");
        JsonObject object;
        FillServiceInfoItem(object, info);
        allProxyObj.PushBack(object);
    }
    JsonObject allSereviceIdObj(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
    for (auto &id : serviceId) {
        allSereviceIdObj.PushBack(id);
    }
    syncMsgJson[TAG_SERVICE_INFOS] = allProxyObj.Dump();
    syncMsgJson[TAG_SERVICE_ID] = allSereviceIdObj.Dump();
    return;
}

int32_t DmAuthMessageProcessor::CreateProxyAccessMessage(std::shared_ptr<DmAuthContext> &context,
    JsonObject &syncMsgJson)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    auto &targetList = context->isServiceBind ? context->subjectServiceOnes : context->subjectProxyOnes;
    auto targetKey = context->isServiceBind ? PARAM_KEY_SUBJECT_SERVICE_ONES : PARAM_KEY_SUBJECT_PROXYED_SUBJECTS;
    if (!context->IsProxyBind || targetList.empty()) {
        return DM_OK;
    }
    JsonObject allProxyObj(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
    for (const auto &app : targetList) {
        DmProxyAccess access;
        JsonObject object;
        if (context->direction == DM_AUTH_SOURCE) {
            access = app.proxyAccesser;
        } else {
            access = app.proxyAccessee;
            std::string serviceInfo = "";
            object[TAG_ACCESSEE_SERVICE_INFO] = serviceInfo;
        }
        if (access.isAuthed) {
            continue;
        }
        object[TAG_PROXY_CONTEXT_ID] = app.proxyContextId;
        object[TAG_TOKEN_ID] = access.tokenId;
        if (!context->isServiceBind) {
            object[TAG_BUNDLE_NAME] = access.bundleName;
        }
        object[TAG_BIND_LEVEL] = access.bindLevel;
        object[TAG_PKG_NAME] = access.pkgName;
        object[TAG_TRANSMIT_SK_ID] = std::to_string(access.transmitSessionKeyId);
        object[TAG_TRANSMIT_SK_TIMESTAMP] = access.skTimeStamp;
        object[TAG_TRANSMIT_CREDENTIAL_ID] = access.transmitCredentialId;
        object[TAG_SRC_SUBJECT_PKGNAME] = app.proxyAccesser.pkgName;
        object[TAG_SUBJECT_SERVICEID] = app.proxyAccessee.serviceId;
        allProxyObj.PushBack(object);
    }
    syncMsgJson[targetKey] = allProxyObj.Dump();
    return DM_OK;
}
//LCOV_EXCL_STOP

int32_t DmAuthMessageProcessor::ACLToStr(DistributedDeviceProfile::AccessControlProfile acl, std::string aclStr)
{
    DmAccessControlTable dmAcl;
    dmAcl.accessControlId = acl.GetAccessControlId();
    dmAcl.accesserId = acl.GetAccesserId();
    dmAcl.accesseeId = acl.GetAccesseeId();
    dmAcl.deviceId = acl.GetTrustDeviceId();
    dmAcl.sessionKey = acl.GetSessionKey();
    dmAcl.bindType = static_cast<int32_t>(acl.GetBindType());
    dmAcl.authType = acl.GetAuthenticationType();
    dmAcl.deviceType = acl.GetDeviceIdType();
    dmAcl.deviceIdHash = acl.GetDeviceIdHash();
    dmAcl.status = acl.GetStatus();
    dmAcl.validPeriod = acl.GetValidPeriod();
    dmAcl.lastAuthTime = acl.GetLastAuthTime();
    dmAcl.bindLevel = acl.GetBindType();
    JsonObject aclJsonObj{};
    aclJsonObj = dmAcl;
    aclStr = aclJsonObj.Dump();
    if (aclStr.empty()) {
        LOGE("normalized acl failed");
        return ERR_DM_FAILED;
    }
    return DM_OK;
}

int32_t DmAuthMessageProcessor::CreateSyncMessage(std::shared_ptr<DmAuthContext> context, JsonObject &jsonObject)
{
    DmAccess accessSide;
    if (context->direction == DM_AUTH_SOURCE) {
        accessSide = context->accesser;
    } else {
        accessSide = context->accessee;
    }
    std::string encSyncMsg;
    int32_t ret = EncryptSyncMessage(context, accessSide, encSyncMsg);
    if (ret != DM_OK) {
        LOGE("encrypt failed");
        return ret;
    }
    jsonObject[TAG_SYNC] = encSyncMsg;
    return DM_OK;
}

int32_t DmAuthMessageProcessor::ParseAuthStartMessage(const JsonObject &jsonObject,
    std::shared_ptr<DmAuthContext> context)
{
    if (jsonObject.IsDiscarded() || !jsonObject.Contains(TAG_DATA) ||
        !jsonObject[TAG_DATA].IsString()) {
        LOGE("Unlegal json string failed");
        return ERR_DM_FAILED;
    }
    context->transmitData = jsonObject[TAG_DATA].Get<std::string>();

    context->authStateMachine->TransitionTo(std::make_shared<AuthSinkCredentialAuthStartState>());
    return DM_OK;
}

bool DmAuthMessageProcessor::IsExistTheToken(JsonObject &proxyObj, int64_t tokenId)
{
    if (proxyObj.IsDiscarded()) {
        return false;
    }
    for (auto const &item : proxyObj.Items()) {
        if (item.IsDiscarded() || !item.IsNumberInteger()) {
            continue;
        }
        if (tokenId == item.Get<int64_t>()) {
            return true;
        }
    }
    return false;
}
void DmAuthMessageProcessor::SetAclProxyRelate(std::shared_ptr<DmAuthContext> context)
{
    CHECK_NULL_VOID(context);
    auto &targetList = context->isServiceBind ? context->subjectServiceOnes : context->subjectProxyOnes;
    if (!context->IsProxyBind || targetList.empty()) {
        return;
    }
    DmAccess &access = (context->direction == DM_AUTH_SOURCE) ? context->accesser : context->accessee;
    DmAccess &remoteAccess = (context->direction == DM_AUTH_SOURCE) ? context->accessee : context->accesser;
    for (auto &app : targetList) {
        DmProxyAccess &proxyAccess = (context->direction == DM_AUTH_SOURCE) ? app.proxyAccesser : app.proxyAccessee;
        if (!proxyAccess.isAuthed || proxyAccess.aclProfiles.find(DM_POINT_TO_POINT) ==
            proxyAccess.aclProfiles.end()) {
            continue;
        }
        SetAclProxyRelate(context, proxyAccess.aclProfiles[DM_POINT_TO_POINT]);
    }
}

void DmAuthMessageProcessor::SetAclProxyRelate(std::shared_ptr<DmAuthContext> context,
    DistributedDeviceProfile::AccessControlProfile &profile)
{
    DmAccess &access = (context->direction == DM_AUTH_SOURCE) ? context->accesser : context->accessee;
    DmAccess &remoteAccess = (context->direction == DM_AUTH_SOURCE) ? context->accessee : context->accesser;
    bool isNeedUpdateProxy = false;
    int64_t tokenId = access.deviceId == profile.GetAccesser().GetAccesserDeviceId() ? access.tokenId :
        remoteAccess.tokenId;
    isNeedUpdateProxy = MergeProxyTokenToAccesser(profile, tokenId) || isNeedUpdateProxy;
    tokenId = access.deviceId == profile.GetAccesser().GetAccesserDeviceId() ? remoteAccess.tokenId : access.tokenId;
    isNeedUpdateProxy = MergeProxyTokenToAccessee(profile, tokenId) || isNeedUpdateProxy;
    if (isNeedUpdateProxy) {
        DistributedDeviceProfile::DistributedDeviceProfileClient::GetInstance().UpdateAccessControlProfile(profile);
    }
}

void ToJson(JsonItemObject &itemObject, const DmAccessControlTable &table)
{
    itemObject["accessControlId"] = table.accessControlId;
    itemObject["accesserId"] = table.accesserId;
    itemObject["accesseeId"] = table.accesseeId;
    itemObject["deviceId"] = table.deviceId;
    itemObject["sessionKey"] = table.sessionKey;
    itemObject["bindType"] = table.bindType;
    itemObject["authType"] = table.authType;
    itemObject["deviceType"] = table.deviceType;
    itemObject["deviceIdHash"] = table.deviceIdHash;
    itemObject["status"] = table.status;
    itemObject["validPeriod"] = table.validPeriod;
    itemObject["lastAuthTime"] = table.lastAuthTime;
    itemObject["bindLevel"] = table.bindLevel;
}

void FromJson(const JsonItemObject &itemObject, DmAccessControlTable &table)
{
    SetValueFromJson(itemObject, "accessControlId", &JsonItemObject::IsNumberInteger, table.accessControlId);
    SetValueFromJson(itemObject, "accesserId", &JsonItemObject::IsNumberInteger, table.accesserId);
    SetValueFromJson(itemObject, "accesseeId", &JsonItemObject::IsNumberInteger, table.accesseeId);
    SetValueFromJson(itemObject, "deviceId", &JsonItemObject::IsNumberInteger, table.deviceId);
    SetValueFromJson(itemObject, "sessionKey", &JsonItemObject::IsString, table.sessionKey);
    SetValueFromJson(itemObject, "bindType", &JsonItemObject::IsNumberInteger, table.bindType);
    SetValueFromJson(itemObject, "authType", &JsonItemObject::IsNumberInteger, table.authType);
    SetValueFromJson(itemObject, "deviceType", &JsonItemObject::IsNumberInteger, table.deviceType);
    SetValueFromJson(itemObject, "deviceIdHash", &JsonItemObject::IsString, table.deviceIdHash);
    SetValueFromJson(itemObject, "status", &JsonItemObject::IsNumberInteger, table.status);
    SetValueFromJson(itemObject, "validPeriod", &JsonItemObject::IsNumberInteger, table.validPeriod);
    SetValueFromJson(itemObject, "lastAuthTime", &JsonItemObject::IsNumberInteger, table.lastAuthTime);
    SetValueFromJson(itemObject, "bindLevel", &JsonItemObject::IsNumberInteger, table.bindLevel);
}

void ToJson(JsonItemObject &itemObject, const DmAccessToSync &table)
{
    itemObject["deviceName"] = table.deviceName;
    itemObject["deviceNameFull"] = table.deviceNameFull;
    itemObject["deviceId"] = table.deviceId;
    itemObject["userId"] = table.userId;
    itemObject["accountId"] = table.accountId;
    itemObject["tokenId"] = table.tokenId;
    itemObject["bundleName"] = table.bundleName;
    itemObject["pkgName"] = table.pkgName;
    itemObject["bindLevel"] = table.bindLevel;
    itemObject["sessionKeyId"] = table.sessionKeyId;
    itemObject["skTimeStamp"] = table.skTimeStamp;
}

void FromJson(const JsonItemObject &itemObject, DmAccessToSync &table)
{
    SetValueFromJson(itemObject, "deviceName", &JsonItemObject::IsString, table.deviceName);
    SetValueFromJson(itemObject, "deviceNameFull", &JsonItemObject::IsString, table.deviceNameFull);
    SetValueFromJson(itemObject, "deviceId", &JsonItemObject::IsString, table.deviceId);
    SetValueFromJson(itemObject, "userId", &JsonItemObject::IsNumberInteger, table.userId);
    SetValueFromJson(itemObject, "accountId", &JsonItemObject::IsString, table.accountId);
    SetValueFromJson(itemObject, "tokenId", &JsonItemObject::IsNumberInteger, table.tokenId);
    SetValueFromJson(itemObject, "bundleName", &JsonItemObject::IsString, table.bundleName);
    SetValueFromJson(itemObject, "pkgName", &JsonItemObject::IsString, table.pkgName);
    SetValueFromJson(itemObject, "bindLevel", &JsonItemObject::IsNumberInteger, table.bindLevel);
    SetValueFromJson(itemObject, "sessionKeyId", &JsonItemObject::IsNumberInteger, table.sessionKeyId);
    SetValueFromJson(itemObject, "skTimeStamp", &JsonItemObject::IsNumberInteger, table.skTimeStamp);
}
} // namespace DistributedHardware
} // namespace OHOS
