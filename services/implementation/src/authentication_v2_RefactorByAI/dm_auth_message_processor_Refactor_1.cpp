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

#include <algorithm>

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
#include "dm_softbus_cache.h"
#include "i_dm_service_impl_ext_resident.h"

namespace OHOS {
namespace DistributedHardware {

const char* TAG_LNN_PUBLIC_KEY = "lnnPublicKey";
const char* TAG_TRANSMIT_PUBLIC_KEY = "transmitPublicKey";
const char* TAG_LNN_CREDENTIAL_ID = "lnnCredentialId";
const char* TAG_TRANSMIT_CREDENTIAL_ID = "transmitCredentialId";
const char* TAG_CONFIRM_OPERATION_V2 = "confirmOperation";
const char* TAG_AUTH_TYPE_LIST = "authTypeList";
const char* TAG_CURRENT_AUTH_TYPE_IDX = "currentAuthTypeIdx";

// IS interface input parameter json format string key
const char* TAG_METHOD = "method";
const char* TAG_PEER_USER_SPACE_ID = "peerUserSpaceId";
const char* TAG_SUBJECT = "subject";
const char* TAG_CRED_TYPE = "credType";
const char* TAG_KEY_FORMAT = "keyFormat";
const char* TAG_ALGORITHM_TYPE = "algorithmType";
const char* TAG_PROOF_TYPE = "proofType";
const char* TAG_KEY_VALUE = "keyValue";
const char* TAG_AUTHORIZED_SCOPE = "authorizedScope";
const char* TAG_AUTHORIZED_APP_LIST = "authorizedAppList";
const char* TAG_CREDENTIAL_OWNER = "credOwner";
const char* TAG_SYNC = "syncMessage";
const char* TAG_ACCESS = "dmAccess";
const char* TAG_PROXY = "proxy";
const char* TAG_PROXY_SERVICE_ID = "proxyServiceId";
const char* TAG_SRC_SUBJECT_PKGNAME = "srcSubjectPkgname";
const char* TAG_SUBJECT_SERVICEID = "subjectServiceId";
const char* TAG_ACL = "accessControlTable";
const char* TAG_ACCESSER = "dmAccesser";
const char* TAG_ACCESSEE = "dmAccessee";
const char* TAG_SERVICEINFO = "serviceInfo";
const char* TAG_USER_CONFIRM_OPT = "userConfirmOpt";
// The local SK information is synchronized to the remote end to construct acl-accesser/accessee.
const char* TAG_TRANSMIT_SK_ID = "accessAppSKId";
const char* TAG_LNN_SK_ID = "accessUserSKId";
const char* TAG_TRANSMIT_SK_TIMESTAMP = "accessAppSKTimeStamp";
const char* TAG_LNN_SK_TIMESTAMP = "accessUserSKTimeStamp";
const char* TAG_USER_ID = "userId";
const char* TAG_TOKEN_ID = "tokenId";
const char* TAG_NETWORKID_ID = "networkId";
const char* TAG_ISSUER = "issuer";

const char* TAG_DEVICE_VERSION = "deviceVersion";
const char* TAG_DEVICE_NAME = "deviceName";
const char* TAG_DEVICE_ID_HASH = "deviceIdHash";
const char* TAG_ACCOUNT_ID_HASH = "accountIdHash";
const char* TAG_ACCOUNT_ID = "accountId";
const char* TAG_TOKEN_ID_HASH = "tokenIdHash";
const char* TAG_PKG_NAME = "pkgName";
const char* TAG_ACL_CHECKSUM = "aclCheckSum";
const char* TAG_COMPRESS_ORI_LEN = "compressOriLen";
const char* TAG_COMPRESS = "compressMsg";
const char* TAG_STATE = "state";
const char* TAG_REASON = "reason";
const char* TAG_PEER_USER_ID = "peerUserId";
const char* TAG_PEER_DISPLAY_ID = "peerDisplayId";
const char* TAG_DEVICE_TYPE_IN_ACL = "deviceType";
const char* TAG_LOCAL_DISPLAY_ID = "localDisplayId";
const char* TAG_EXTRA_INFO = "extraInfo";
const char* TAG_ACL_TYPE_LIST = "aclTypeList";
const char* TAG_CERT_TYPE_LIST = "certTypeList";
const char* TAG_SERVICE_CODE = "serviceCode";

const char* TAG_IS_ONLINE = "isOnline";
const char* TAG_IS_AUTHED = "isAuthed";
const char* TAG_CREDENTIAL_INFO = "credentialInfo";
const char* TAG_CERT_INFO = "certInfo";
const char* TAG_LANGUAGE = "language";
const char* TAG_ULTRASONIC_SIDE = "ultrasonicSide";
const char* TAG_REMAINING_FROZEN_TIME = "remainingFrozenTime";
const char* TAG_IS_SUPPORT_ULTRASONIC = "isSupportUltrasonic";
const char* TAG_ACCESSEE_SERVICE_INFO = "accesseeServiceInfo";
const char* TAG_REG_SERVICE_ID = "regServiceId";
const char* TAG_PUBLISH_STATE = "publishState";
const char* TAG_SERVICE_TYPE = "serviceType";
const char* TAG_SERVICE_NAME = "serviceName";
const char* TAG_SERVICE_DISPLAY_NAME = "serviceDisplayName";

const char* TAG_SERVICE_INFOS = "serviceInfos";

// Wipe and release the session key heap buffer.
static void FreeSessionKeyMemory(DMSessionKey &sessionKey)
{
    if (sessionKey.key != nullptr) {
        (void)memset_s(sessionKey.key, sessionKey.keyLen, 0, sessionKey.keyLen);
        free(sessionKey.key);
        sessionKey.key = nullptr;
        sessionKey.keyLen = 0;
    }
}

static DistributedDeviceProfile::AccessControlProfile GetSubjectAccessControlProfile(
    std::shared_ptr<DmAuthContext> context, DmProxyAuthContext app, bool &hasAcl)
{
    LOGI("start.");
    DistributedDeviceProfile::AccessControlProfile profile;
    if (context == nullptr) {
        LOGE("GetAccessControlProfile context is null.");
        return profile;
    }
    std::vector<DistributedDeviceProfile::AccessControlProfile> accessControlProfiles;
    int32_t ret = DistributedDeviceProfile::DistributedDeviceProfileClient::GetInstance().
        GetAllAccessControlProfile(accessControlProfiles);
    if (ret != DM_OK) {
        LOGE("GetAllAccessControlProfile failed.");
        return profile;
    }
    for (const auto& item : accessControlProfiles) {
        std::string acerDeviceId = item.GetAccesser().GetAccesserDeviceId();
        int64_t acerTokenId = item.GetAccesser().GetAccesserTokenId();
        int32_t acerUserId = item.GetAccesser().GetAccesserUserId();
        std::string aceeDeviceId = item.GetAccessee().GetAccesseeDeviceId();
        int64_t aceeTokenId = item.GetAccessee().GetAccesseeTokenId();
        int32_t aceeUserId = item.GetAccessee().GetAccesseeUserId();
        if (context->accesser.deviceId == acerDeviceId && context->accesser.userId == acerUserId &&
            context->accessee.deviceId == aceeDeviceId && app.proxyAccesser.tokenId == acerTokenId &&
            context->accessee.userId == aceeUserId && context->accessee.tokenId == aceeTokenId) {
            LOGI("match success.");
            hasAcl = true;
            profile = item;
            break;
        }
        continue;
    }
    return profile;
}

// Notify the service online result if the peer device is online.
static void NotifyServiceStateOnline(std::shared_ptr<DmAuthContext> context, int64_t serviceId)
{
    ServiceStateBindParameter bindParam = {context->accesser.tokenId, context->accesser.pkgName,
        DM_POINT_TO_POINT, context->accessee.deviceId, context->accessee.userId, serviceId};
    char deviceIdHash[DM_MAX_DEVICE_ID_LEN] = {0};
    Crypto::GetUdidHash(context->accessee.deviceId, reinterpret_cast<uint8_t *>(deviceIdHash));
    if (SoftbusCache::GetInstance().CheckIsOnline(std::string(deviceIdHash))) {
        context->listener->OnServiceStateOnlineResult(bindParam);
    }
}

static void UpdateMatchAccessControlProfile(std::shared_ptr<DmAuthContext> context,
    DistributedDeviceProfile::AccessControlProfile &profile, bool &hasAcl, int64_t serviceId)
{
    LOGI("start.");
    CHECK_NULL_VOID(context);
    JsonObject jsonObjServiceId(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
    bool isServiceIdExist = false;
    std::string aceeSeviceId = profile.GetAccessee().GetAccesseeExtraData();
    JsonObject lastServiceId;
    if (!lastServiceId.Parse(aceeSeviceId)) {
        LOGE("Failed to parse JSON string");
        return;
    }
    if (lastServiceId.Contains(TAG_SERVICE_ID) && lastServiceId[TAG_SERVICE_ID].IsArray()) {
        auto tmpServiceId = lastServiceId[TAG_SERVICE_ID];
        for (auto& id : tmpServiceId.Items()) {
            int64_t idValue = id.Get<int64_t>();
            if (idValue != serviceId) {
                jsonObjServiceId.PushBack(idValue);
            } else {
                isServiceIdExist = true;
            }
        }
        if (!isServiceIdExist) {
            jsonObjServiceId.PushBack(serviceId);
        }
        lastServiceId.Insert(TAG_SERVICE_ID, jsonObjServiceId);
        DistributedDeviceProfile::Accessee accessee = profile.GetAccessee();
        accessee.SetAccesseeExtraData(lastServiceId.Dump());
        profile.SetAccessee(accessee);
        ret = DistributedDeviceProfile::DistributedDeviceProfileClient::GetInstance().UpdateAccessControlProfile(
            profile);
        if (ret != DM_OK) {
            LOGE("UpdateAccessControlProfile failed.");
        } else {
            NotifyServiceStateOnline(context, serviceId);
        }
    } else {
        hasAcl = false;
    }
}

static void SetAccessExtraData(std::shared_ptr<DmAuthContext> context, bool &hasAcl,
    DistributedDeviceProfile::AccessControlProfile &profile)
{
    LOGI("start.");
    CHECK_NULL_VOID(context);
    JsonObject jsonObjAccesser;
    JsonObject jsonObjAccessee;
    JsonObject jsonObjServiceId(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
    jsonObjAccesser[TAG_DMVERSION] = context->accesser.dmVersion;
    jsonObjAccesser[TAG_PKG_NAME] = context->accesser.pkgName;
    jsonObjAccessee[TAG_DMVERSION] = context->accessee.dmVersion;
    if (hasAcl) {
        UpdateMatchAccessControlProfile(context, profile, hasAcl, context->accessee.serviceId);
    }
    jsonObjServiceId.PushBack(context->accessee.serviceId);
    jsonObjAccessee.Insert(TAG_SERVICE_ID, jsonObjServiceId);
    context->accesser.extraInfo = jsonObjAccesser.Dump();
    context->accessee.extraInfo = jsonObjAccessee.Dump();
}

static void SetSubjectAccessExtraData(std::shared_ptr<DmAuthContext> context, DmProxyAuthContext &subject, bool &hasAcl,
    DistributedDeviceProfile::AccessControlProfile &profile)
{
    LOGI("start.");
    CHECK_NULL_VOID(context);
    JsonObject jsonObjAccesser;
    JsonObject jsonObjAccessee;
    JsonObject jsonObjServiceId(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
    JsonObject jsonObjAccesserProxy(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
    JsonObject jsonObjAccesseeProxy(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
    jsonObjAccesserProxy.PushBack(context->accesser.tokenId);
    jsonObjAccesser[TAG_DMVERSION] = context->accesser.dmVersion;
    jsonObjAccesser[TAG_PKG_NAME] = subject.proxyAccesser.pkgName;
    jsonObjAccesser[TAG_PROXY] = jsonObjAccesserProxy.Dump();
    jsonObjAccessee[TAG_DMVERSION] = context->accessee.dmVersion;
    DistributedDeviceProfile::ServiceInfo dpServiceInfo;
    int32_t ret = DeviceProfileConnector::GetInstance().GetServiceInfoByUdidAndServiceId(
        context->accessee.deviceId, subject.proxyAccessee.serviceId, dpServiceInfo);
    if (ret != DM_OK) {
        LOGE("GetServiceInfoByUdidAndServiceId failed, ret %{public}d.", ret);
    }
    int64_t proxyTokenid = dpServiceInfo.GetServiceRegisterTokenId();
    jsonObjAccesseeProxy.PushBack(proxyTokenid);
    jsonObjAccessee[TAG_PROXY] = jsonObjAccesseeProxy.Dump();
    if (hasAcl) {
        UpdateMatchAccessControlProfile(context, profile, hasAcl, subject.proxyAccessee.serviceId);
    }
    jsonObjServiceId.PushBack(subject.proxyAccessee.serviceId);
    jsonObjAccessee.Insert(TAG_SERVICE_ID, jsonObjServiceId);
    subject.proxyAccesser.extraInfo = jsonObjAccesser.Dump();
    subject.proxyAccessee.extraInfo = jsonObjAccessee.Dump();
}

static bool ShouldWriteAclLifeCycleDays(std::shared_ptr<DmAuthContext> context)
{
    return context->confirmOperation == UiAction::USER_OPERATION_TYPE_ALLOW_AUTH_ALWAYS &&
        context->aclLifeCycleDays >= ACL_LIFE_CYCLE_DAYS_MIN &&
        context->aclLifeCycleDays <= ACL_LIFE_CYCLE_DAYS_MAX;
}

int32_t DmAuthMessageProcessor::SaveSessionKey(const uint8_t *sessionKey, const uint32_t keyLen)
{
    if (cryptoMgr_ == nullptr) {
        LOGE("cryptoMgr_ is nullptr.");
        return ERR_DM_FAILED;
    }
    return cryptoMgr_->ProcessSessionKey(sessionKey, keyLen);
}

int32_t DmAuthMessageProcessor::SaveSessionKeyToDP(int32_t userId, int32_t &skId)
{
    if (cryptoMgr_ == nullptr) {
        LOGE("cryptoMgr_ is nullptr.");
        return ERR_DM_FAILED;
    }
    return DeviceProfileConnector::GetInstance().PutSessionKey(userId, cryptoMgr_->GetSessionKey(), skId);
}

int32_t DmAuthMessageProcessor::SaveDerivativeSessionKeyToDP(int32_t userId, const std::string &suffix, int32_t &skId)
{
    if (cryptoMgr_ == nullptr) {
        LOGE("cryptoMgr_ is nullptr.");
        return ERR_DM_FAILED;
    }
    std::vector<unsigned char> sessionKey = cryptoMgr_->GetSessionKey();
    size_t keyLen = sessionKey.size();
    std::string keyStr(sessionKey.begin(), sessionKey.end());
    std::string newKeyStr = Crypto::Sha256(keyStr + suffix);
    ClearSensitiveString(keyStr);
    DMSessionKey newSessionKey;
    newSessionKey.key = nullptr;
    newSessionKey.keyLen = 0;
    size_t newKeyLen = std::min(keyLen, newKeyStr.size());
    if (newKeyLen == 0 || newKeyLen > MAX_SESSION_KEY_LENGTH) {
        LOGE("newKeyLen invaild, cannot allocate memory.");
        ClearSensitiveString(newKeyStr);
        return ERR_DM_FAILED;
    }
    newSessionKey.key = (uint8_t*)calloc(newKeyLen, sizeof(uint8_t));
    if (newSessionKey.key == nullptr) {
        LOGE("calloc session key memory failed.");
        ClearSensitiveString(newKeyStr);
        return ERR_DM_FAILED;
    }
    newSessionKey.keyLen = newKeyLen;
    if (memcpy_s(newSessionKey.key, newKeyLen, newKeyStr.c_str(), newKeyLen) != DM_OK) {
        LOGE("copy key data failed.");
        FreeSessionKeyMemory(newSessionKey);
        ClearSensitiveString(newKeyStr);
        return ERR_DM_FAILED;
    }
    int32_t ret = DeviceProfileConnector::GetInstance().PutSessionKey(userId,
        std::vector<unsigned char>(newSessionKey.key, newSessionKey.key + newSessionKey.keyLen), skId);
    if (ret != DM_OK) {
        LOGE("DP save user session key failed %{public}d", ret);
    }
    FreeSessionKeyMemory(newSessionKey);
    ClearSensitiveString(newKeyStr);
    return ret;
}

int32_t DmAuthMessageProcessor::GetSessionKey(int32_t userId, int32_t &skId)
{
    std::vector<unsigned char> sessionKey;
    int32_t ret = DeviceProfileConnector::GetInstance().GetSessionKey(userId, skId, sessionKey);
    if (ret != DM_OK) {
        LOGE("failed: %{public}d", ret);
        return ret;
    }
    int32_t procRet = ERR_DM_POINT_NULL;
    if (cryptoMgr_ != nullptr) {
        procRet = cryptoMgr_->ProcessSessionKey(sessionKey.data(), sessionKey.size());
    } else {
        LOGE("cryptoMgr_ is nullptr.");
    }
    std::fill(sessionKey.begin(), sessionKey.end(), 0);
    return procRet;
}

int32_t DmAuthMessageProcessor::DeleteSessionKeyToDP(int32_t userId, int32_t skId)
{
    return DeviceProfileConnector::GetInstance().DeleteSessionKey(userId, skId);
}

void DmAuthMessageProcessor::SetAccessControlList(std::shared_ptr<DmAuthContext> context,
    DistributedDeviceProfile::AccessControlProfile &profile)
{
    uint32_t authenticationType = ALLOW_AUTH_ONCE;
    if (context->confirmOperation == USER_OPERATION_TYPE_ALLOW_AUTH_ALWAYS) {
        authenticationType = ALLOW_AUTH_ALWAYS;
    }
    profile.SetAuthenticationType(authenticationType);
    profile.SetStatus(ACTIVE);
    profile.SetDeviceIdType((int32_t)DistributedDeviceProfile::DeviceIdType::UDID);
}

void DmAuthMessageProcessor::SetTransmitAccessControlList(std::shared_ptr<DmAuthContext> context,
    DistributedDeviceProfile::Accesser &accesser, DistributedDeviceProfile::Accessee &accessee)
{
    accesser.SetAccesserDeviceId(context->accesser.deviceId);
    accesser.SetAccesserUserId(context->accesser.userId);
    accesser.SetAccesserAccountId(context->accesser.accountId);
    accesser.SetAccesserTokenId(context->accesser.tokenId);
    accesser.SetAccesserBundleName(context->accesser.pkgName);
    accesser.SetAccesserDeviceName(context->accesser.deviceName);
    accesser.SetAccesserCredentialIdStr(context->accesser.transmitCredentialId);
    accesser.SetAccesserSessionKeyId(context->accesser.transmitSessionKeyId);
    accesser.SetAccesserSKTimeStamp(context->accesser.transmitSkTimeStamp);
    JsonObject accesserExtObj;
    if (!context->accesser.extraInfo.empty()) {
        accesserExtObj.Parse(context->accesser.extraInfo);
    }
    if (!accesserExtObj.IsDiscarded()) {
        accesserExtObj[TAG_DEVICE_TYPE_IN_ACL] = context->accesser.deviceType;
        accesser.SetAccesserExtraData(accesserExtObj.Dump());
    }
    accessee.SetAccesseeDeviceId(context->accessee.deviceId);
    accessee.SetAccesseeUserId(context->accessee.userId);
    accessee.SetAccesseeAccountId(context->accessee.accountId);
    accessee.SetAccesseeTokenId(context->accessee.tokenId);
    accessee.SetAccesseeBundleName(context->accessee.pkgName);
    accessee.SetAccesseeDeviceName(context->accessee.deviceName);
    accessee.SetAccesseeCredentialIdStr(context->accessee.transmitCredentialId);
    accessee.SetAccesseeSessionKeyId(context->accessee.transmitSessionKeyId);
    accessee.SetAccesseeSKTimeStamp(context->accessee.transmitSkTimeStamp);
    JsonObject accesseeExtObj;
    if (!context->accessee.extraInfo.empty()) {
        accesseeExtObj.Parse(context->accessee.extraInfo);
    }
    if (!accesseeExtObj.IsDiscarded()) {
        accesseeExtObj[TAG_DEVICE_TYPE_IN_ACL] = context->accessee.deviceType;
        accessee.SetAccesseeExtraData(accesseeExtObj.Dump());
    }
}

void DmAuthMessageProcessor::SetLnnAccessControlList(std::shared_ptr<DmAuthContext> context,
    DistributedDeviceProfile::Accesser &accesser, DistributedDeviceProfile::Accessee &accessee)
{
    accesser.SetAccesserDeviceId(context->accesser.deviceId);
    accesser.SetAccesserUserId(context->accesser.userId);
    accesser.SetAccesserAccountId(context->accesser.accountId);
    accesser.SetAccesserTokenId(0);
    accesser.SetAccesserDeviceName(context->accesser.deviceName);
    accesser.SetAccesserCredentialIdStr(context->accesser.lnnCredentialId);
    accesser.SetAccesserSessionKeyId(context->accesser.lnnSessionKeyId);
    accesser.SetAccesserSKTimeStamp(context->accesser.lnnSkTimeStamp);
    JsonObject accesserExtObj;
    bool isAccesserExtValid = true;
    if (!context->accesser.extraInfo.empty()) {
        isAccesserExtValid = accesserExtObj.Parse(context->accesser.extraInfo);
    }
    if (isAccesserExtValid && !accesserExtObj.IsDiscarded()) {
        accesserExtObj[TAG_DEVICE_TYPE_IN_ACL] = context->accesser.deviceType;
        accesser.SetAccesserExtraData(accesserExtObj.Dump());
    } else {
        LOGE("accesser extraInfo is invalid json, keep original extraData.");
    }

    accessee.SetAccesseeDeviceId(context->accessee.deviceId);
    accessee.SetAccesseeUserId(context->accessee.userId);
    accessee.SetAccesseeAccountId(context->accessee.accountId);
    accessee.SetAccesseeTokenId(0);
    accessee.SetAccesseeDeviceName(context->accessee.deviceName);
    accessee.SetAccesseeCredentialIdStr(context->accessee.lnnCredentialId);
    accessee.SetAccesseeSessionKeyId(context->accessee.lnnSessionKeyId);
    accessee.SetAccesseeSKTimeStamp(context->accessee.lnnSkTimeStamp);
    JsonObject accesseeExtObj;
    bool isAccesseeExtValid = true;
    if (!context->accessee.extraInfo.empty()) {
        isAccesseeExtValid = accesseeExtObj.Parse(context->accessee.extraInfo);
    }
    if (isAccesseeExtValid && !accesseeExtObj.IsDiscarded()) {
        accesseeExtObj[TAG_DEVICE_TYPE_IN_ACL] = context->accessee.deviceType;
        accessee.SetAccesseeExtraData(accesseeExtObj.Dump());
    } else {
        LOGE("accessee extraInfo is invalid json, keep original extraData.");
    }
}

bool DmAuthMessageProcessor::CheckMatchServiceAcl(std::shared_ptr<DmAuthContext> &context,
    const DistributedDeviceProfile::AccessControlProfile &acl)
{
    LOGI("start");
    CHECK_NULL_RETURN(context, false);
    CHECK_NULL_RETURN(context->softbusConnector, false);
    std::string acerDeviceId = acl.GetAccesser().GetAccesserDeviceId();
    int64_t acerTokenId = acl.GetAccesser().GetAccesserTokenId();
    int32_t acerUserId = acl.GetAccesser().GetAccesserUserId();
    std::string aceeDeviceId = acl.GetAccessee().GetAccesseeDeviceId();
    int64_t aceeTokenId = acl.GetAccessee().GetAccesseeTokenId();
    int32_t aceeUserId = acl.GetAccessee().GetAccesseeUserId();
    std::string acerAccountId = acl.GetAccesser().GetAccesserAccountId();
    std::string aceeAccountId = acl.GetAccessee().GetAccesseeAccountId();
    bool accountIdMatch = (context->accesser.accountIdHash == Crypto::GetAccountIdHash16(acerAccountId)) &&
        (context->accessee.accountIdHash == Crypto::GetAccountIdHash16(aceeAccountId));
    if (context->accesser.deviceId == acerDeviceId && context->accesser.userId == acerUserId &&
        context->accessee.deviceId == aceeDeviceId && context->accesser.tokenId == acerTokenId &&
        context->accessee.userId == aceeUserId && context->accessee.tokenId == aceeTokenId &&
        accountIdMatch && !context->softbusConnector->CheckAclInDeleteCache(acl.GetAccessControlId())) {
        return true;
    }
    return false;
}
// LCOV_EXCL_START
DistributedDeviceProfile::AccessControlProfile DmAuthMessageProcessor::GetAvailableServiceAcl(
    std::shared_ptr<DmAuthContext> context, bool &hasAcl, bool &isNeedLnn)
{
    LOGI("start.");
    DistributedDeviceProfile::AccessControlProfile profile;
    if (context == nullptr) {
        LOGE("context is null.");
        return profile;
    }
    std::vector<DistributedDeviceProfile::AccessControlProfile> accessControlProfiles;
    int32_t ret = DistributedDeviceProfile::DistributedDeviceProfileClient::GetInstance().
        GetAllAccessControlProfile(accessControlProfiles);
    if (ret != DM_OK) {
        LOGE("GetAllAccessControlProfile failed.");
        return profile;
    }
    for (const auto& item : accessControlProfiles) {
        uint32_t bindLevel = item.GetAccesser().GetAccesserBindLevel();
        if (CheckMatchServiceAcl(context, item)) {
            if (bindLevel == USER) {
                isNeedLnn = false;
                continue;
            }
            LOGI("match success.");
            hasAcl = true;
            profile = item;
            break;
        }
    }
    return profile;
}

int32_t DmAuthMessageProcessor::PutServiceControlList(std::shared_ptr<DmAuthContext> context,
                                                      DistributedDeviceProfile::Accesser accesser,
                                                      DistributedDeviceProfile::Accessee accessee,
                                                      DistributedDeviceProfile::AccessControlProfile profile,
                                                      DmAccess &access)
{
    LOGI("Start.");
    CHECK_NULL_RETURN(context, ERR_DM_INPUT_PARA_INVALID);
    bool hasAcl = false;
    bool isNeedLnn = true;
    JsonObject extraData;
    DistributedDeviceProfile::AccessControlProfile matchProfile = GetAvailableServiceAcl(context, hasAcl, isNeedLnn);
    SetAccessExtraData(context, hasAcl, matchProfile);
    if (access.isPutLnnAcl && access.bindLevel != static_cast<int32_t>(USER) && isNeedLnn) {
        LOGI("lnn inner.");
        profile.SetBindLevel(USER);
        std::string isLnnAclTrue = std::string(ACL_IS_LNN_ACL_VAL_TRUE);
        extraData[ACL_IS_LNN_ACL_KEY] = isLnnAclTrue;
        extraData[TAG_SERVICE_ID] = access.serviceId;
        profile.SetExtraData(extraData.Dump());
        int32_t ret =
            DistributedDeviceProfile::DistributedDeviceProfileClient::GetInstance().PutAccessControlProfile(profile);
        if (ret != DM_OK) {
            LOGE("PutAccessControlProfile failed.");
        }
    }
    accesser.SetAccesserExtraData(context->accesser.extraInfo);
    accessee.SetAccesseeExtraData(context->accessee.extraInfo);
    bool isAuthed = (context->direction == DM_AUTH_SOURCE) ? context->accesser.isAuthed : context->accessee.isAuthed;
    if ((!context->IsProxyBind || context->subjectServiceOnes.empty() ||
        (context->IsCallingProxyAsSubject && !isAuthed)) && !hasAcl) {
        PutNonLnnAclProfile(context, access, profile, accesser, accessee, extraData);
    }

    return PutServiceAccessControlList(context, profile, accesser, accessee);
}

void DmAuthMessageProcessor::PutNonLnnAclProfile(std::shared_ptr<DmAuthContext> context, DmAccess &access,
    DistributedDeviceProfile::AccessControlProfile &profile,
    DistributedDeviceProfile::Accesser &accesser,
    DistributedDeviceProfile::Accessee &accessee,
    JsonObject &extraData)
{
    LOGI("PutNonLnnAclProfile.");
    CHECK_NULL_VOID(context);
    extraData[ACL_IS_LNN_ACL_KEY] = std::string(ACL_IS_LNN_ACL_VAL_FALSE);
    if (ShouldWriteAclLifeCycleDays(context)) {
        extraData[ACL_LIFE_CYCLE_DAYS] = context->aclLifeCycleDays;
    }
    profile.SetExtraData(extraData.Dump());
    profile.SetBindLevel(access.bindLevel);

    SetTransmitAccessControlList(context, accesser, accessee);
    profile.SetBindLevel(access.bindLevel);
    profile.SetBindType(access.transmitBindType);
    profile.SetAccessee(accessee);
    profile.SetAccesser(accesser);

    int32_t ret =
        DistributedDeviceProfile::DistributedDeviceProfileClient::GetInstance().PutAccessControlProfile(profile);
    if (ret != DM_OK) {
        LOGE("PutAccessControlProfile failed.");
        return;
    }

    NotifyServiceStateOnline(context, context->accessee.serviceId);
    LOGI("call BindServiceOnline in PutServiceControlList");
}

int32_t DmAuthMessageProcessor::PutDeviceControlList(std::shared_ptr<DmAuthContext> context,
    DistributedDeviceProfile::Accesser accesser, DistributedDeviceProfile::Accessee accessee,
    DistributedDeviceProfile::AccessControlProfile profile, DmAccess &access)
{
    JsonObject extraData;
    if (access.isPutLnnAcl && access.bindLevel != static_cast<int32_t>(USER)) {
        profile.SetBindLevel(USER);
        std::string isLnnAclTrue = std::string(ACL_IS_LNN_ACL_VAL_TRUE);
        extraData[ACL_IS_LNN_ACL_KEY] = isLnnAclTrue;
        extraData[TAG_SERVICE_ID] = access.serviceId;
        profile.SetExtraData(extraData.Dump());
        int32_t ret =
            DistributedDeviceProfile::DistributedDeviceProfileClient::GetInstance().PutAccessControlProfile(profile);
        if (ret != DM_OK) {
            LOGE("PutAccessControlProfile failed.");
        }
    }
    bool isAuthed = (context->direction == DM_AUTH_SOURCE) ? context->accesser.isAuthed : context->accessee.isAuthed;
    if (!context->IsProxyBind || context->subjectProxyOnes.empty() ||
        (context->IsCallingProxyAsSubject && !isAuthed)) {
        std::string isLnnAclFalse = std::string(ACL_IS_LNN_ACL_VAL_FALSE);
        extraData[ACL_IS_LNN_ACL_KEY] = isLnnAclFalse;
        extraData[TAG_SERVICE_ID] = access.serviceId;
        if (ShouldWriteAclLifeCycleDays(context)) {
            extraData[ACL_LIFE_CYCLE_DAYS] = context->aclLifeCycleDays;
        }
        profile.SetExtraData(extraData.Dump());
        profile.SetBindLevel(access.bindLevel);
        SetTransmitAccessControlList(context, accesser, accessee);
        profile.SetBindLevel(access.bindLevel);
        profile.SetBindType(access.transmitBindType);
        profile.SetAccessee(accessee);
        profile.SetAccesser(accesser);
        int32_t ret =
            DistributedDeviceProfile::DistributedDeviceProfileClient::GetInstance().PutAccessControlProfile(profile);
        if (ret != DM_OK) {
            LOGE("PutAccessControlProfile failed.");
        }
    }
    return PutProxyAccessControlList(context, profile, accesser, accessee);
}

int32_t DmAuthMessageProcessor::PutAccessControlList(std::shared_ptr<DmAuthContext> context,
    DmAccess &access, std::string trustDeviceId)
{
    LOGI("Start.");
    CHECK_NULL_RETURN(context, ERR_DM_INPUT_PARA_INVALID);
    DistributedDeviceProfile::Accesser accesser;
    DistributedDeviceProfile::Accessee accessee;
    SetLnnAccessControlList(context, accesser, accessee);
    DistributedDeviceProfile::AccessControlProfile profile;
    SetAccessControlList(context, profile);
    profile.SetTrustDeviceId(trustDeviceId);
    profile.SetDeviceIdHash(access.deviceIdHash);
    profile.SetBindType(access.lnnBindType);
    profile.SetAccessee(accessee);
    profile.SetAccesser(accesser);
    if (context->isServiceBind) {
        return PutServiceControlList(context, accesser, accessee, profile, access);
    } else {
        return PutDeviceControlList(context, accesser, accessee, profile, access);
    }
}

int32_t DmAuthMessageProcessor::SetProxyAccess(std::shared_ptr<DmAuthContext> context,
    DmProxyAuthContext &proxyAuthContext, DistributedDeviceProfile::Accesser &accesser,
    DistributedDeviceProfile::Accessee &accessee)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    accesser.SetAccesserTokenId(proxyAuthContext.proxyAccesser.tokenId);
    accesser.SetAccesserBundleName(proxyAuthContext.proxyAccesser.bundleName);
    accesser.SetAccesserCredentialIdStr(proxyAuthContext.proxyAccesser.transmitCredentialId);
    accesser.SetAccesserSessionKeyId(proxyAuthContext.proxyAccesser.transmitSessionKeyId);
    accesser.SetAccesserSKTimeStamp(proxyAuthContext.proxyAccesser.skTimeStamp);
    JsonObject accesserProxyObj(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
    accesserProxyObj.PushBack(context->accesser.tokenId);
    JsonObject accesserExtObj;
    bool isAccesserExtValid = true;
    if (!context->accesser.extraInfo.empty()) {
        isAccesserExtValid = accesserExtObj.Parse(context->accesser.extraInfo);
    }
    if (isAccesserExtValid && !accesserExtObj.IsDiscarded()) {
        accesserExtObj[TAG_PROXY] = accesserProxyObj.Dump();
        accesserExtObj[TAG_DEVICE_TYPE_IN_ACL] = context->accesser.deviceType;
        accesser.SetAccesserExtraData(accesserExtObj.Dump());
    } else {
        LOGE("accesser extraInfo is invalid json, keep original extraData.");
    }

    accessee.SetAccesseeTokenId(proxyAuthContext.proxyAccessee.tokenId);
    accessee.SetAccesseeBundleName(proxyAuthContext.proxyAccessee.bundleName);
    accessee.SetAccesseeCredentialIdStr(proxyAuthContext.proxyAccessee.transmitCredentialId);
    accessee.SetAccesseeSessionKeyId(proxyAuthContext.proxyAccessee.transmitSessionKeyId);
    accessee.SetAccesseeSKTimeStamp(proxyAuthContext.proxyAccessee.skTimeStamp);
    JsonObject accesseeProxyObj(JsonCreateType::JSON_CREATE_TYPE_ARRAY);
    accesseeProxyObj.PushBack(context->accessee.tokenId);
    JsonObject accesseeExtObj;
    bool isAccesseeExtValid = true;
    if (!context->accessee.extraInfo.empty()) {
        isAccesseeExtValid = accesseeExtObj.Parse(context->accessee.extraInfo);
    }
    if (isAccesseeExtValid && !accesseeExtObj.IsDiscarded()) {
        accesseeExtObj[TAG_PROXY] = accesseeProxyObj.Dump();
        accesseeExtObj[TAG_DEVICE_TYPE_IN_ACL] = context->accessee.deviceType;
        accessee.SetAccesseeExtraData(accesseeExtObj.Dump());
    } else {
        LOGE("accessee extraInfo is invalid json, keep original extraData.");
    }
    return DM_OK;
}

int32_t DmAuthMessageProcessor::PutServiceAccessControlList(std::shared_ptr<DmAuthContext> context,
    DistributedDeviceProfile::AccessControlProfile &profile, DistributedDeviceProfile::Accesser &accesser,
    DistributedDeviceProfile::Accessee &accessee)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    if (!context->IsProxyBind || context->subjectServiceOnes.empty()) {
        return DM_OK;
    }

    for (auto &app : context->subjectServiceOnes) {
        if (context->direction == DM_AUTH_SOURCE ? app.proxyAccesser.isAuthed : app.proxyAccessee.isAuthed) {
            LOGI("continue.");
            continue;
        }
        bool hasAcl = false;
        DistributedDeviceProfile::AccessControlProfile matchProfile =
            GetSubjectAccessControlProfile(context, app, hasAcl);
        SetProxyAccess(context, app, accesser, accessee);
        JsonObject extraData;
        std::string isLnnAclFalse = std::string(ACL_IS_LNN_ACL_VAL_FALSE);
        extraData[ACL_IS_LNN_ACL_KEY] = isLnnAclFalse;
        if (ShouldWriteAclLifeCycleDays(context)) {
            extraData[ACL_LIFE_CYCLE_DAYS] = context->aclLifeCycleDays;
        }
        profile.SetExtraData(extraData.Dump());
        profile.SetBindLevel(context->direction == DM_AUTH_SOURCE ? app.proxyAccesser.bindLevel :
            app.proxyAccessee.bindLevel);
        profile.SetBindType(context->direction == DM_AUTH_SOURCE ? context->accesser.transmitBindType :
            context->accessee.transmitBindType);
        SetSubjectAccessExtraData(context, app, hasAcl, matchProfile);
        if (hasAcl) {
            LOGE("has acl.");
            continue;
        }
        accesser.SetAccesserExtraData(app.proxyAccesser.extraInfo);
        accessee.SetAccesseeExtraData(app.proxyAccessee.extraInfo);
        profile.SetAccessee(accessee);
        profile.SetAccesser(accesser);
        int32_t ret =
            DistributedDeviceProfile::DistributedDeviceProfileClient::GetInstance().PutAccessControlProfile(profile);
        if (ret != DM_OK) {
            LOGE("failed. %{public}d", ret);
            return ret;
        }
        NotifyServiceStateOnline(context, context->accessee.serviceId);
    }
    return DM_OK;
}
// LCOV_EXCL_STOP
int32_t DmAuthMessageProcessor::PutProxyAccessControlList(std::shared_ptr<DmAuthContext> context,
    DistributedDeviceProfile::AccessControlProfile &profile, DistributedDeviceProfile::Accesser &accesser,
    DistributedDeviceProfile::Accessee &accessee)
{
    CHECK_NULL_RETURN(context, ERR_DM_POINT_NULL);
    if (!context->IsProxyBind || context->subjectProxyOnes.empty()) {
        return DM_OK;
    }
    for (auto &app : context->subjectProxyOnes) {
        if (context->direction == DM_AUTH_SOURCE ? app.proxyAccesser.isAuthed : app.proxyAccessee.isAuthed) {
            continue;
        }
        SetProxyAccess(context, app, accesser, accessee);
        JsonObject extraData;
        std::string isLnnAclFalse = std::string(ACL_IS_LNN_ACL_VAL_FALSE);
        extraData[ACL_IS_LNN_ACL_KEY] = isLnnAclFalse;
        if (ShouldWriteAclLifeCycleDays(context)) {
            extraData[ACL_LIFE_CYCLE_DAYS] = context->aclLifeCycleDays;
        }
        profile.SetExtraData(extraData.Dump());
        profile.SetBindLevel(context->direction == DM_AUTH_SOURCE ? app.proxyAccesser.bindLevel :
            app.proxyAccessee.bindLevel);
        profile.SetBindType(context->direction == DM_AUTH_SOURCE ? context->accesser.transmitBindType :
            context->accessee.transmitBindType);
        profile.SetAccessee(accessee);
        profile.SetAccesser(accesser);
        int32_t ret =
            DistributedDeviceProfile::DistributedDeviceProfileClient::GetInstance().PutAccessControlProfile(profile);
        if (ret != DM_OK) {
            LOGE("PutAccessControlProfile failed. %{public}d", ret);
            return ret;
        }
    }
    SetAclProxyRelate(context);
    return DM_OK;
}

void DmAuthMessageProcessor::ConstructCreateMessageFuncMap()
{
    createMessageFuncMap_ = {
        {DmMessageType::MSG_TYPE_REQ_ACL_NEGOTIATE, &DmAuthMessageProcessor::CreateNegotiateMessage},
        {DmMessageType::MSG_TYPE_RESP_ACL_NEGOTIATE, &DmAuthMessageProcessor::CreateRespNegotiateMessage},
        {DmMessageType::MSG_TYPE_REQ_USER_CONFIRM, &DmAuthMessageProcessor::CreateMessageReqUserConfirm},
        {DmMessageType::MSG_TYPE_RESP_USER_CONFIRM, &DmAuthMessageProcessor::CreateMessageRespUserConfirm},
        {DmMessageType::MSG_TYPE_REQ_PIN_AUTH_START, &DmAuthMessageProcessor::CreateMessageReqPinAuthStart},
        {DmMessageType::MSG_TYPE_REQ_PIN_AUTH_MSG_NEGOTIATE, &DmAuthMessageProcessor::CreateMessageReqPinAuthNegotiate},
        {DmMessageType::MSG_TYPE_RESP_PIN_AUTH_START, &DmAuthMessageProcessor::CreateMessageRespPinAuthStart},
        {DmMessageType::MSG_TYPE_RESP_PIN_AUTH_MSG_NEGOTIATE,
            &DmAuthMessageProcessor::CreateMessageRespPinAuthNegotiate},
        {DmMessageType::MSG_TYPE_REQ_CREDENTIAL_EXCHANGE, &DmAuthMessageProcessor::CreateMessageReqCredExchange},
        {DmMessageType::MSG_TYPE_RESP_CREDENTIAL_EXCHANGE, &DmAuthMessageProcessor::CreateMessageRspCredExchange},
        {DmMessageType::MSG_TYPE_REQ_SK_DERIVE, &DmAuthMessageProcessor::CreateMessageReqSKDerive},
        {DmMessageType::MSG_TYPE_RESP_SK_DERIVE, &DmAuthMessageProcessor::CreateMessageRspSKDerive},
        {DmMessageType::MSG_TYPE_REQ_CREDENTIAL_AUTH_START, &DmAuthMessageProcessor::CreateMessageReqCredAuthStart},
        {DmMessageType::MSG_TYPE_REQ_CREDENTIAL_AUTH_NEGOTIATE,
            &DmAuthMessageProcessor::CreateCredentialNegotiateMessage},
        {DmMessageType::MSG_TYPE_RESP_CREDENTIAL_AUTH_START, &DmAuthMessageProcessor::CreateCredentialNegotiateMessage},
        {DmMessageType::MSG_TYPE_RESP_CREDENTIAL_AUTH_NEGOTIATE,
            &DmAuthMessageProcessor::CreateCredentialNegotiateMessage},
        {DmMessageType::MSG_TYPE_REQ_DATA_SYNC, &DmAuthMessageProcessor::CreateSyncMessage},
        {DmMessageType::MSG_TYPE_RESP_DATA_SYNC, &DmAuthMessageProcessor::CreateMessageSyncResp},
        {DmMessageType::MSG_TYPE_AUTH_REQ_FINISH, &DmAuthMessageProcessor::CreateMessageFinish},
        {DmMessageType::MSG_TYPE_AUTH_RESP_FINISH, &DmAuthMessageProcessor::CreateMessageFinish},
    };
}

void DmAuthMessageProcessor::ConstructParseMessageFuncMap()
{
    paraseMessageFuncMap_ = {
        {DmMessageType::MSG_TYPE_REQ_ACL_NEGOTIATE, &DmAuthMessageProcessor::ParseNegotiateMessage},
        {DmMessageType::MSG_TYPE_RESP_ACL_NEGOTIATE, &DmAuthMessageProcessor::ParseMessageRespAclNegotiate},
        {DmMessageType::MSG_TYPE_REQ_USER_CONFIRM, &DmAuthMessageProcessor::ParseMessageReqUserConfirm},
        {DmMessageType::MSG_TYPE_RESP_USER_CONFIRM, &DmAuthMessageProcessor::ParseMessageRespUserConfirm},
        {DmMessageType::MSG_TYPE_REQ_PIN_AUTH_START, &DmAuthMessageProcessor::ParseMessageReqPinAuthStart},
        {DmMessageType::MSG_TYPE_REQ_PIN_AUTH_MSG_NEGOTIATE, &DmAuthMessageProcessor::ParseMessageReqPinAuthNegotiate},
        {DmMessageType::MSG_TYPE_RESP_PIN_AUTH_START, &DmAuthMessageProcessor::ParseMessageRespPinAuthStart},
        {DmMessageType::MSG_TYPE_RESP_PIN_AUTH_MSG_NEGOTIATE,
            &DmAuthMessageProcessor::ParseMessageRespPinAuthNegotiate},
        {DmMessageType::MSG_TYPE_REQ_CREDENTIAL_EXCHANGE, &DmAuthMessageProcessor::ParseMessageReqCredExchange},
        {DmMessageType::MSG_TYPE_RESP_CREDENTIAL_EXCHANGE, &DmAuthMessageProcessor::ParseMessageRspCredExchange},
        {DmMessageType::MSG_TYPE_REQ_SK_DERIVE, &DmAuthMessageProcessor::ParseMessageReqSKDerive},
        {DmMessageType::MSG_TYPE_RESP_SK_DERIVE, &DmAuthMessageProcessor::ParseMessageRspSKDerive},
        {DmMessageType::MSG_TYPE_REQ_CREDENTIAL_AUTH_START, &DmAuthMessageProcessor::ParseAuthStartMessage},
        {DmMessageType::MSG_TYPE_REQ_CREDENTIAL_AUTH_NEGOTIATE, &DmAuthMessageProcessor::ParseMessageNegotiateTransmit},
        {DmMessageType::MSG_TYPE_RESP_CREDENTIAL_AUTH_START, &DmAuthMessageProcessor::ParseMessageNegotiateTransmit},
        {DmMessageType::MSG_TYPE_RESP_CREDENTIAL_AUTH_NEGOTIATE,
            &DmAuthMessageProcessor::ParseMessageNegotiateTransmit},
        {DmMessageType::MSG_TYPE_REQ_DATA_SYNC, &DmAuthMessageProcessor::ParseMessageSyncReq},
        {DmMessageType::MSG_TYPE_RESP_DATA_SYNC, &DmAuthMessageProcessor::ParseMessageSyncResp},
        {DmMessageType::MSG_TYPE_AUTH_REQ_FINISH, &DmAuthMessageProcessor::ParseMessageSinkFinish},
        {DmMessageType::MSG_TYPE_AUTH_RESP_FINISH, &DmAuthMessageProcessor::ParseMessageSrcFinish},
    };
}

DmAuthMessageProcessor::DmAuthMessageProcessor()
{
    LOGI("constructor");
    cryptoMgr_ = std::make_shared<CryptoMgr>();
    ConstructCreateMessageFuncMap();
    ConstructParseMessageFuncMap();
    DmAuthUltrasonicMessageProcessor();
}

DmAuthMessageProcessor::~DmAuthMessageProcessor()
{
    if (cryptoMgr_ != nullptr) {
        cryptoMgr_->ClearSessionKey();
        cryptoMgr_ = nullptr;
    }
}

} // namespace DistributedHardware
} // namespace OHOS
