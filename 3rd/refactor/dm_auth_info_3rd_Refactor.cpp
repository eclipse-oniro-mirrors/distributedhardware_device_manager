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

#include "dm_auth_info_3rd_Refactor.h"

#include <cstring>
#include <algorithm>
#include <string>
#include <securec.h>

#include "json_object.h"
#include "dm_anonymous_3rd.h"

namespace OHOS {
namespace DistributedHardware {

static void ParseAccess3rdStringField(const JsonItemObject &obj,
    const std::string &key, std::string &value)
{
    if (obj.Contains(key) && obj[key].IsString()) {
        value = obj[key].Get<std::string>();
    }
}

static void ParseAccess3rdIntField(const JsonItemObject &obj,
    const std::string &key, int32_t &value)
{
    if (obj.Contains(key) && obj[key].IsNumberInteger()) {
        value = obj[key].Get<int32_t>();
    }
}

static void ParseAccess3rdUintField(const JsonItemObject &obj,
    const std::string &key, uint32_t &value)
{
    if (obj.Contains(key) && obj[key].IsNumberInteger()) {
        value = obj[key].Get<uint32_t>();
    }
}

void ToJson(JsonItemObject &itemObject, const Access3rdRefactor &access)
{
    itemObject["deviceId"] = access.deviceId;
    itemObject["userId"] = access.userId;
    itemObject["accountId"] = access.accountId;
    itemObject["tokenId"] = access.tokenId;
    itemObject["processName"] = access.processName;
    itemObject["uid"] = access.uid;
    itemObject["businessName"] = access.businessName;
    itemObject["version"] = access.version;
}

void FromJson(const JsonItemObject &itemObject, Access3rdRefactor &access)
{
    ParseAccess3rdStringField(itemObject, "deviceId", access.deviceId);
    ParseAccess3rdIntField(itemObject, "userId", access.userId);
    ParseAccess3rdStringField(itemObject, "accountId", access.accountId);
    ParseAccess3rdUintField(itemObject, "tokenId", access.tokenId);
    ParseAccess3rdStringField(itemObject, "processName", access.processName);
    ParseAccess3rdIntField(itemObject, "uid", access.uid);
    ParseAccess3rdStringField(itemObject, "businessName", access.businessName);
    ParseAccess3rdStringField(itemObject, "version", access.version);
}

void ToJson(JsonItemObject &itemObject, const AccessControl3rdRefactor &accessControl)
{
    itemObject["trustDeviceId"] = accessControl.trustDeviceId;
    itemObject["sessionKeyId"] = accessControl.sessionKeyId;
    itemObject["createTime"] = accessControl.createTime;
    itemObject["accesser"] = accessControl.accesser;
    itemObject["accessee"] = accessControl.accessee;
    itemObject["extra"] = accessControl.extra;
    itemObject["bindLevel"] = accessControl.bindLevel;
    itemObject["bindType"] = accessControl.bindType;
}

void FromJson(const JsonItemObject &itemObject, AccessControl3rdRefactor &accessControl)
{
    if (IsString(itemObject, "trustDeviceId")) {
        accessControl.trustDeviceId = itemObject["trustDeviceId"].Get<std::string>();
    }
    if (IsInt32(itemObject, "sessionKeyId")) {
        accessControl.sessionKeyId = itemObject["sessionKeyId"].Get<int32_t>();
    }
    if (IsInt64(itemObject, "createTime")) {
        accessControl.createTime = itemObject["createTime"].Get<int64_t>();
    }
    if (itemObject.Contains("accesser") && itemObject["accesser"].IsObject()) {
        FromJson(itemObject["accesser"], accessControl.accesser);
    }
    if (itemObject.Contains("accessee") && itemObject["accessee"].IsObject()) {
        FromJson(itemObject["accessee"], accessControl.accessee);
    }
    if (IsString(itemObject, "extra")) {
        accessControl.extra = itemObject["extra"].Get<std::string>();
    }
    if (IsInt32(itemObject, "bindLevel")) {
        accessControl.bindLevel = itemObject["bindLevel"].Get<int32_t>();
    }
    if (IsInt32(itemObject, "bindType")) {
        accessControl.bindType = itemObject["bindType"].Get<int32_t>();
    }
}

void ToJson(JsonItemObject &itemObject, const TrustDeviceInfo3rdRefactor &trustDeviceInfo)
{
    itemObject["trustDeviceId"] = trustDeviceInfo.trustDeviceId;
    itemObject["sessionKeyId"] = trustDeviceInfo.sessionKeyId;
    itemObject["createTime"] = trustDeviceInfo.createTime;
    itemObject["userId"] = trustDeviceInfo.userId;
    itemObject["extra"] = trustDeviceInfo.extra;
    itemObject["bindLevel"] = trustDeviceInfo.bindLevel;
    itemObject["bindType"] = trustDeviceInfo.bindType;
}

void FromJson(const JsonItemObject &itemObject, TrustDeviceInfo3rdRefactor &trustDeviceInfo)
{
    if (IsString(itemObject, "trustDeviceId")) {
        trustDeviceInfo.trustDeviceId = itemObject["trustDeviceId"].Get<std::string>();
    }
    if (IsInt32(itemObject, "sessionKeyId")) {
        trustDeviceInfo.sessionKeyId = itemObject["sessionKeyId"].Get<int32_t>();
    }
    if (IsInt64(itemObject, "createTime")) {
        trustDeviceInfo.createTime = itemObject["createTime"].Get<int64_t>();
    }
    if (IsInt32(itemObject, "userId")) {
        trustDeviceInfo.userId = itemObject["userId"].Get<int32_t>();
    }
    if (IsString(itemObject, "extra")) {
        trustDeviceInfo.extra = itemObject["extra"].Get<std::string>();
    }
    if (IsInt32(itemObject, "bindLevel")) {
        trustDeviceInfo.bindLevel = itemObject["bindLevel"].Get<int32_t>();
    }
    if (IsInt32(itemObject, "bindType")) {
        trustDeviceInfo.bindType = itemObject["bindType"].Get<int32_t>();
    }
}

void FreeDeviceInfos(std::vector<TrustDeviceInfo3rdRefactor> &deviceInfos)
{
    for (auto &deviceInfo : deviceInfos) {
        if (deviceInfo.sessionKey.key != nullptr) {
            (void)memset_s(deviceInfo.sessionKey.key,
                deviceInfo.sessionKey.keyLen, 0, deviceInfo.sessionKey.keyLen);
            free(deviceInfo.sessionKey.key);
            deviceInfo.sessionKey.key = nullptr;
            deviceInfo.sessionKey.keyLen = 0;
        }
    }
}
} // namespace DistributedHardware
} // namespace OHOS
