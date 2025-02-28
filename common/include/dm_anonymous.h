/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_DM_ANONYMOUS_H
#define OHOS_DM_ANONYMOUS_H

#include <map>
#include <string>
#include "nlohmann/json.hpp"
#include "dm_device_info.h"

namespace OHOS {
namespace DistributedHardware {
extern const char* PRINT_LIST_SPLIT;
extern const int32_t LIST_SPLIT_LEN;

std::string GetAnonyString(const std::string &value);
std::string GetAnonyStringList(const std::vector<std::string> &values);
std::string GetAnonyInt32(const int32_t value);
std::string GetAnonyInt32List(const std::vector<int32_t> &values);
bool IsNumberString(const std::string &inputString);
bool IsString(const nlohmann::json &jsonObj, const std::string &key);
bool IsInt32(const nlohmann::json &jsonObj, const std::string &key);
bool IsUint32(const nlohmann::json &jsonObj, const std::string &key);
bool IsInt64(const nlohmann::json &jsonObj, const std::string &key);
bool IsArray(const nlohmann::json &jsonObj, const std::string &key);
bool IsBool(const nlohmann::json &jsonObj, const std::string &key);
std::string ConvertMapToJsonString(const std::map<std::string, std::string> &paramMap);
void ParseMapFromJsonString(const std::string &jsonStr, std::map<std::string, std::string> &paramMap);
bool IsInvalidPeerTargetId(const PeerTargetId &targetId);
std::string ConvertCharArray2String(const char *srcData, uint32_t srcLen);
int32_t StringToInt(const std::string &str, int32_t base);
int64_t StringToInt64(const std::string &str, int32_t base);
void VersionSplitToInt(const std::string &str, const char split, std::vector<int32_t> &numVec);
bool CompareVecNum(const std::vector<int32_t> &srcVecNum, const std::vector<int32_t> &sinkVecNum);
bool CompareVersion(const std::string &remoteVersion, const std::string &oldVersion);
std::string ComposeStr(const std::string &pkgName, uint16_t subscribeId);
std::string GetCallerPkgName(const std::string &pkgName);
uint16_t GetSubscribeId(const std::string &pkgName);
template <class T>
std::string GetAnonyInteger(const T value)
{
    std::string tempString = std::to_string(value);
    size_t length = tempString.length();
    if (length == 0x01) {
        tempString[0] = '*';
        return tempString;
    }
    for (size_t i = 1; i < length - 1; i++) {
        tempString[i] = '*';
    }
    return tempString;
}

template <class T>
std::string GetAnonyIntegerList(const std::vector<T> &values)
{
    std::string temp = "[ ";
    bool flag = false;
    for (auto const &v : values) {
        temp += GetAnonyInteger(v) + PRINT_LIST_SPLIT;
        flag = true;
    }
    if (flag) {
        temp.erase(temp.length() - LIST_SPLIT_LEN);
    }
    temp += " ]";
    return temp;
}

template <class T>
std::string GetIntegerList(const std::vector<T> &values)
{
    std::string temp = "[ ";
    bool flag = false;
    for (auto const &v : values) {
        temp += std::to_string(v) + PRINT_LIST_SPLIT;
        flag = true;
    }
    if (flag) {
        temp.erase(temp.length() - LIST_SPLIT_LEN);
    }
    temp += " ]";
    return temp;
}

bool IsIdLengthValid(const std::string &inputID);
bool IsMessageLengthValid(const std::string &inputMessage);
bool IsValueExist(const std::multimap<std::string, int32_t> unorderedmap, const std::string &udid, int32_t userId);
bool IsDmCommonNotifyEventValid(DmCommonNotifyEvent dmCommonNotifyEvent);
std::string SafetyDump(const nlohmann::json &jsonObj);
std::string GetSubStr(const std::string &rawStr, const std::string &separator, int32_t index);
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_ANONYMOUS_H
