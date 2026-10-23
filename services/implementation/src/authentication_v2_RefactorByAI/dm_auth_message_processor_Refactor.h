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

constexpr const char* TAG_NCM_BIND_TARGET = "ncm_bind_target";
constexpr const char* TAG_CUSTOM_DESCRIPTION = "CUSTOMDESC";

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

// Json keys defined in dm_auth_message_processor_Refactor_1.cpp and shared by all parts.
extern const char* TAG_SERVICE_INFOS;
extern const char* TAG_ACL_TYPE_LIST;
extern const char* TAG_CERT_TYPE_LIST;
extern const char* TAG_IS_SUPPORT_ULTRASONIC;
extern const char* TAG_ACCESSEE_SERVICE_INFO;
extern const char* TAG_REG_SERVICE_ID;
extern const char* TAG_PUBLISH_STATE;
extern const char* TAG_SERVICE_TYPE;
extern const char* TAG_SERVICE_NAME;
extern const char* TAG_SERVICE_DISPLAY_NAME;

// ---- Shared helpers ----
// Wipe sensitive string content before release.
inline void ClearSensitiveString(std::string &sensitiveData)
{
    if (!sensitiveData.empty()) {
        (void)memset_s(const_cast<char *>(sensitiveData.data()), sensitiveData.size(), 0, sensitiveData.size());
        sensitiveData.clear();
    }
}

// Shared helper functions declared here and defined in dm_auth_message_processor_Refactor_1.cpp.
bool ParseDmAccessToSync(const std::string &jsonString, DmAccess &access, bool isUseDeviceFullName);
void SaveToDmAccessSync(DmAccessToSync &accessToSync, const std::shared_ptr<DmAuthContext> context,
    const DmAccess &accessSide);
int32_t ParseInfoToDmAccess(const JsonObject &jsonObject, DmAccess &access);

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

bool GetPinMatchFlag(const std::string &pkgName, DmAuthType authType);

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
