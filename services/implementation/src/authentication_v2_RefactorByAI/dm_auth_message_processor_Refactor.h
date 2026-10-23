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

#ifndef OHOS_DM_AUTH_MESSAGE_PROCESSOR_V2_REFACTOR_H
#define OHOS_DM_AUTH_MESSAGE_PROCESSOR_V2_REFACTOR_H

#include <sstream>
#include <string>
#include <vector>

#include "securec.h"

#include "dm_auth_message_processor.h"
#include "dm_anonymous.h"
#include "dm_auth_context.h"
#include "dm_constants.h"
#include "dm_crypto.h"
#include "dm_log.h"

namespace OHOS {
namespace DistributedHardware {

// ---- Shared constants ----
constexpr int32_t DM_HASH_LEN = 32;
constexpr const char* TAG_DEVICE_TYPE = "DEVICETYPE";
constexpr int32_t DM_ULTRASONIC_FORWARD = 0;
constexpr int32_t DM_ULTRASONIC_REVERSE = 1;
constexpr uint32_t MAX_SESSION_KEY_LENGTH = 512;
constexpr uint32_t MAX_MESSAGE_LENGTH = 64 * 1024 * 1024;

const char* TAG_NCM_BIND_TARGET = "ncm_bind_target";
constexpr const char* TAG_CUSTOM_DESCRIPTION = "CUSTOMDESC";

const char* SERVICEINFO_USER_ID = "userId";
const char* SERVICEINFO_SERVICE_ID = "serviceId";
const char* SERVICEINFO_DISPLAY_ID = "displayId";
const char* SERVICEINFO_PUBLISH_STATE = "publishState";
const char* SERVICEINFO_DEVICE_ID = "deviceId";
const char* SERVICEINFO_NETWORK_ID = "networkId";
const char* SERVICEINFO_SERVICE_OWNER_TOKEN_ID = "serviceOwnerTokenId";
const char* SERVICEINFO_SERVICE_OWNER_PKG_NAME = "serviceOwnerPkgName";
const char* SERVICEINFO_SERVICE_REGISTER_TOKEN_ID = "serviceRegisterTokenId";
const char* SERVICEINFO_SERVICE_TYPE = "serviceType";
const char* SERVICEINFO_SERVICE_NAME = "serviceName";
const char* SERVICEINFO_SERVICE_DISPLAY_NAME = "serviceDisplayName";
const char* SERVICEINFO_SERVICE_CODE = "serviceCode";
const char* SERVICEINFO_CUSTOM_DATA = "customData";
const char* SERVICEINFO_DATA_LEN = "dataLen";
const char* SERVICEINFO_TIME_STAMP = "timeStamp";
const char* SERVICEINFO_VERSION = "version";
const char* SERVICEINFO_EXTRA_DATA = "extraData";
const char* SERVICEINFO_DESCRIPTION = "description";

// ---- Shared helpers ----
// Wipe sensitive string content before release.
inline void ClearSensitiveString(std::string &sensitiveData)
{
    if (!sensitiveData.empty()) {
        (void)memset_s(const_cast<char *>(sensitiveData.data()), sensitiveData.size(), 0, sensitiveData.size());
        sensitiveData.clear();
    }
}

inline bool ParseDmAccessToSync(const std::string &jsonString, DmAccess &access, bool isUseDeviceFullName)
{
    JsonObject accessjson(jsonString);
    if (accessjson.IsDiscarded()) {
        LOGE("ParseDmAccessToSync jsonStr error");
        return false;
    }
    DmAccessToSync srcAccessToSync = accessjson.Get<DmAccessToSync>();
    access.deviceName = (isUseDeviceFullName ? srcAccessToSync.deviceNameFull : srcAccessToSync.deviceName);
    access.deviceId = srcAccessToSync.deviceId;
    access.userId = srcAccessToSync.userId;
    access.accountId = srcAccessToSync.accountId;
    access.tokenId = static_cast<int64_t>(srcAccessToSync.tokenId);
    access.bundleName = srcAccessToSync.bundleName;
    access.pkgName = srcAccessToSync.pkgName;
    access.bindLevel = srcAccessToSync.bindLevel;
    access.sessionKeyId = srcAccessToSync.sessionKeyId;
    access.skTimeStamp = srcAccessToSync.skTimeStamp;
    return true;
}

inline void SaveToDmAccessSync(DmAccessToSync &accessToSync, const std::shared_ptr<DmAuthContext> context,
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

inline int32_t ParseInfoToDmAccess(const JsonObject &jsonObject, DmAccess &access)
{
    // transmit session key is mandatory
    if (!IsString(jsonObject, TAG_TRANSMIT_SK_ID)) {
        LOGE("ParseSyncMessage TAG_TRANSMIT_SK_ID error");
        return ERR_DM_FAILED;
    }
    access.transmitSessionKeyId = std::atoi(jsonObject[TAG_TRANSMIT_SK_ID].Get<std::string>().c_str());

    if (!IsInt64(jsonObject, TAG_TRANSMIT_SK_TIMESTAMP)) {
        LOGE("ParseSyncMessage TAG_TRANSMIT_SK_TIMESTAMP error");
        return ERR_DM_FAILED;
    }
    access.transmitSkTimeStamp = jsonObject[TAG_TRANSMIT_SK_TIMESTAMP].Get<int64_t>();

    if (!IsString(jsonObject, TAG_TRANSMIT_CREDENTIAL_ID)) {
        LOGE("ParseSyncMessage TAG_TRANSMIT_CREDENTIAL_ID error");
        return ERR_DM_FAILED;
    }
    access.transmitCredentialId = jsonObject[TAG_TRANSMIT_CREDENTIAL_ID].Get<std::string>().c_str();

    if (!IsString(jsonObject, TAG_DMVERSION)) {
        LOGE("ParseSyncMessage TAG_DMVERSION error");
        return ERR_DM_FAILED;
    }
    access.dmVersion = jsonObject[TAG_DMVERSION].Get<std::string>();

    if (IsInt64(jsonObject, TAG_PROXY_SERVICE_ID)) {
        access.serviceId = jsonObject[TAG_PROXY_SERVICE_ID].Get<int64_t>();
    }

    // lnn session key is optional
    if (IsString(jsonObject, TAG_LNN_SK_ID)) {
        access.lnnSessionKeyId = std::atoi(jsonObject[TAG_LNN_SK_ID].Get<std::string>().c_str());
    }
    if (IsInt64(jsonObject, TAG_LNN_SK_TIMESTAMP)) {
        access.lnnSkTimeStamp = jsonObject[TAG_LNN_SK_TIMESTAMP].Get<int64_t>();
    }

    if (IsString(jsonObject, TAG_LNN_CREDENTIAL_ID)) {
        access.lnnCredentialId = jsonObject[TAG_LNN_CREDENTIAL_ID].Get<std::string>().c_str();
    }

    return DM_OK;
}

inline bool IsMessageValid(const JsonItemObject &jsonObject)
{
    if (jsonObject.IsDiscarded()) {
        LOGE("decodeRequestAuth jsonStr error");
        return false;
    }
    if (!jsonObject[TAG_MSG_TYPE].IsNumberInteger()) {
        LOGE("message type error.");
        return false;
    }
    return true;
}

inline bool GetPinMatchFlag(const std::string &pkgName, DmAuthType authType)
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

inline std::vector<DmAuthType> stringToVectorAuthType(const std::string &str)
{
    std::vector<DmAuthType> vec;
    std::istringstream iss(str);
    int32_t num;
    while (iss >> num) {
        vec.push_back(static_cast<DmAuthType>(num));
    }
    return vec;
}

inline std::string vectorAuthTypeToString(const std::vector<DmAuthType> &vec)
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
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_AUTH_MESSAGE_PROCESSOR_V2_REFACTOR_H
