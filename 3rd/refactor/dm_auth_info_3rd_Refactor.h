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

#ifndef OHOS_DM_ACL_AUTH_INFO_3RD_REFACTOR_H
#define OHOS_DM_ACL_AUTH_INFO_3RD_REFACTOR_H

#include <vector>
#include <string>
#include <cstdint>

namespace OHOS {
namespace DistributedHardware {

class JsonItemObject;

struct DmSessionKey3rd {
    uint8_t *key = nullptr;
    uint32_t keyLen = 0;
};

struct Access3rdRefactor {
    std::string deviceId;
    int32_t userId = -1;
    std::string accountId;
    uint32_t tokenId = 0;
    std::string processName;
    int32_t uid = 0;
    std::string businessName;
    std::string version;
};

struct AccessControl3rdRefactor {
    std::string trustDeviceId;
    int32_t sessionKeyId = -1;
    int64_t createTime = 0;
    Access3rdRefactor accesser;
    Access3rdRefactor accessee;
    std::string extra;
    int32_t bindLevel = -1;
    int32_t bindType = -1;
};

struct TrustDeviceInfo3rdRefactor {
    std::string trustDeviceId;
    std::string deviceName;
    std::string businessName;
    std::string extra;
    uint16_t deviceTypeId = 0;
    int32_t sessionKeyId = -1;
    int32_t userId = -1;
    int32_t bindLevel = -1;
    int32_t bindType = -1;
    int64_t createTime = 0;
    DmSessionKey3rd sessionKey;
};

void ToJson(JsonItemObject &itemObject, const Access3rdRefactor &access);
void FromJson(const JsonItemObject &itemObject, Access3rdRefactor &access);
void ToJson(JsonItemObject &itemObject, const AccessControl3rdRefactor &accessControl);
void FromJson(const JsonItemObject &itemObject, AccessControl3rdRefactor &accessControl);
void ToJson(JsonItemObject &itemObject, const TrustDeviceInfo3rdRefactor &trustDeviceInfo);
void FromJson(const JsonItemObject &itemObject, TrustDeviceInfo3rdRefactor &trustDeviceInfo);
void FreeDeviceInfos(std::vector<TrustDeviceInfo3rdRefactor> &deviceInfos);

} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_ACL_AUTH_INFO_3RD_REFACTOR_H
