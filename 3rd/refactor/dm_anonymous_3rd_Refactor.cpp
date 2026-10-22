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
#include "dm_anonymous_3rd_Refactor.h"

#include <sstream>
#include <set>

#include "dm_log_3rd.h"

namespace OHOS {
namespace DistributedHardware {

namespace {
constexpr uint32_t MAX_MESSAGE_LEN = 40 * 1024 * 1024;
constexpr uint32_t MAX_MAP_LEN = 1000;
constexpr size_t MAX_JSON_DEPTH = 10;
constexpr int32_t INT32_SHORT_ID_LENGTH = 20;
constexpr int32_t INT32_PLAIN_TEXT_LENGTH = 4;
constexpr int32_t INT32_MIN_ID_LENGTH = 3;

const std::set<std::string> &GetSensitiveKeys()
{
    static const std::set<std::string> keys = {
        "LOCALDEVICEID", "localAccountId", "networkId", "lnnPublicKey",
        "transmitPublicKey", "DEVICEID", "deviceId", "keyValue",
        "deviceName", "REMOTE_DEVICE_NAME", "data", "accountId",
        "openId", "udid", "uuid"
    };
    return keys;
}
}

std::string GetAnonyString(const std::string &value)
{
    std::string tmpStr("******");
    size_t strLen = value.length();
    if (strLen < INT32_MIN_ID_LENGTH) {
        return tmpStr;
    }
    std::string res;
    if (strLen <= INT32_SHORT_ID_LENGTH) {
        res += value[0];
        res += tmpStr;
        res += value[strLen - 1];
    } else {
        res.append(value, 0, INT32_PLAIN_TEXT_LENGTH);
        res += tmpStr;
        res.append(value, strLen - INT32_PLAIN_TEXT_LENGTH, INT32_PLAIN_TEXT_LENGTH);
    }
    return res;
}

static std::string AnonyNumber(const std::string &tempString)
{
    std::string s = tempString;
    size_t length = s.length();
    if (length == 1) {
        s[0] = '*';
        return s;
    }
    for (size_t i = 1; i < length - 1; i++) {
        s[i] = '*';
    }
    return s;
}

std::string GetAnonyInt32(const int32_t value)
{
    return AnonyNumber(std::to_string(value));
}

std::string GetAnonyUint32(const uint32_t value)
{
    return AnonyNumber(std::to_string(value));
}

static void AnonymizeJsonObject(JsonObject &paramJson,
    const std::set<std::string> &sensitiveKey, size_t depth)
{
    if (depth > MAX_JSON_DEPTH) {
        LOGE("JSON nesting depth exceeded.");
        return;
    }
    for (auto &element : paramJson.Items()) {
        if (element.IsString() && sensitiveKey.find(element.Key()) != sensitiveKey.end()) {
            paramJson[element.Key()] = GetAnonyString(element.Get<std::string>());
        } else if (element.IsObject()) {
            JsonObject nestedJson(element.Dump());
            if (!nestedJson.IsDiscarded()) {
                AnonymizeJsonObject(nestedJson, sensitiveKey, depth + 1);
                paramJson[element.Key()] = nestedJson.Dump();
            }
        }
    }
}

std::string GetAnonyJsonString(const std::string &value)
{
    if (value.empty()) {
        LOGE("Str is empty.");
        return "";
    }
    JsonObject paramJson(value);
    if (paramJson.IsDiscarded()) {
        LOGE("Str is not json string.");
        return "";
    }
    const std::set<std::string> &sensitiveKey = GetSensitiveKeys();
    AnonymizeJsonObject(paramJson, sensitiveKey, 0);
    return paramJson.Dump();
}

bool IsString(const JsonItemObject &jsonObj, const std::string &key)
{
    if (!jsonObj.Contains(key)) {
        LOGE("key:%{public}s not found.", key.c_str());
        return false;
    }
    if (!jsonObj[key].IsString()) {
        LOGE("key:%{public}s is not string.", key.c_str());
        return false;
    }
    if (jsonObj[key].Get<std::string>().size() > MAX_MESSAGE_LEN) {
        LOGE("key:%{public}s is too long.", key.c_str());
        return false;
    }
    return true;
}

bool IsInt32(const JsonItemObject &jsonObj, const std::string &key)
{
    if (!jsonObj.Contains(key)) {
        LOGE("key:%{public}s not found.", key.c_str());
        return false;
    }
    if (!jsonObj[key].IsNumberInteger()) {
        LOGE("key:%{public}s is not integer.", key.c_str());
        return false;
    }
    int64_t val = jsonObj[key].Get<int64_t>();
    if (val < INT32_MIN || val > INT32_MAX) {
        LOGE("key:%{public}s out of int32 range.", key.c_str());
        return false;
    }
    return true;
}

bool IsBool(const JsonItemObject &jsonObj, const std::string &key)
{
    bool res = jsonObj.Contains(key) && jsonObj[key].IsBoolean();
    if (!res) {
        LOGE("key:%{public}s invalid.", key.c_str());
    }
    return res;
}

bool IsInt64(const JsonItemObject &jsonObj, const std::string &key)
{
    if (!jsonObj.Contains(key)) {
        LOGE("key:%{public}s not found.", key.c_str());
        return false;
    }
    if (!jsonObj[key].IsNumberInteger()) {
        LOGE("key:%{public}s is not integer.", key.c_str());
        return false;
    }
    return true;
}

std::string ConvertMapToJsonString(const std::map<std::string, std::string> &paramMap)
{
    std::string jsonStr = "";
    if (paramMap.size() > MAX_MAP_LEN) {
        LOGE("invalid paramMap size.");
        return jsonStr;
    }
    if (!paramMap.empty()) {
        JsonObject jsonObj;
        for (const auto &it : paramMap) {
            jsonObj[it.first] = it.second;
        }
        jsonStr = jsonObj.Dump();
    }
    return jsonStr;
}

void ParseMapFromJsonString(const std::string &jsonStr,
    std::map<std::string, std::string> &paramMap)
{
    if (jsonStr.empty()) {
        return;
    }
    if (paramMap.size() > MAX_MAP_LEN) {
        LOGE("invalid paramMap size.");
        return;
    }
    JsonObject paramJson(jsonStr);
    if (paramJson.IsDiscarded()) {
        return;
    }
    for (auto &element : paramJson.Items()) {
        if (element.IsString()) {
            std::string k = element.Key();
            std::string v = element.Get<std::string>();
            paramMap.insert(std::pair<std::string, std::string>(k, v));
        }
    }
}

bool IsUint64(const JsonItemObject &jsonObj, const std::string &key)
{
    if (!jsonObj.Contains(key)) {
        LOGE("key:%{public}s not found.", key.c_str());
        return false;
    }
    if (!jsonObj[key].IsNumberInteger()) {
        LOGE("key:%{public}s is not integer.", key.c_str());
        return false;
    }
    uint64_t val = jsonObj[key].Get<uint64_t>();
    if (val > UINT64_MAX) {
        LOGE("key:%{public}s out of uint64 range.", key.c_str());
        return false;
    }
    return true;
}

bool IsUint32(const JsonItemObject &jsonObj, const std::string &key)
{
    if (!jsonObj.Contains(key)) {
        LOGE("key:%{public}s not found.", key.c_str());
        return false;
    }
    if (!jsonObj[key].IsNumberInteger()) {
        LOGE("key:%{public}s is not integer.", key.c_str());
        return false;
    }
    int64_t val = jsonObj[key].Get<int64_t>();
    if (val < 0 || val > UINT32_MAX) {
        LOGE("key:%{public}s out of uint32 range.", key.c_str());
        return false;
    }
    return true;
}

bool IsUint8(const JsonItemObject &jsonObj, const std::string &key)
{
    if (!jsonObj.Contains(key)) {
        LOGE("key:%{public}s not found.", key.c_str());
        return false;
    }
    if (!jsonObj[key].IsNumberInteger()) {
        LOGE("key:%{public}s is not integer.", key.c_str());
        return false;
    }
    int64_t val = jsonObj[key].Get<int64_t>();
    if (val < 0 || val > UINT8_MAX) {
        LOGE("key:%{public}s out of uint8 range.", key.c_str());
        return false;
    }
    return true;
}

} // namespace DistributedHardware
} // namespace OHOS
