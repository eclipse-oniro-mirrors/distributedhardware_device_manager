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

#include "dm_3rd_device_cache.h"

#include <algorithm>

#include "dm_anonymous.h"
#include "dm_constants.h"
#include "dm_error_type.h"
#include "dm_log.h"
#include "json_object.h"
#include "securec.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
constexpr int32_t MAX_3RD_DEVICE_CACHE_SIZE = 100;
constexpr int32_t MAX_3RD_EXTEND_PARAM_NUM = 20;
constexpr size_t MAX_3RD_NETWORK_ID_LEN = 96;
constexpr size_t MAX_3RD_DEVICE_NAME_LEN = 128;
constexpr size_t MAX_3RD_EXTEND_PARAM_LEN = 128;
const std::string SYMBOL_NAME_MAP_KEY = "symbolName";
} // namespace

DM_IMPLEMENT_SINGLE_INSTANCE(Dm3rdDeviceCache);

int32_t Dm3rdDeviceCache::CheckInputParam(const Dm3rdDeviceInfo &info) const
{
    if (info.networkId.empty() || info.networkId.length() > MAX_3RD_NETWORK_ID_LEN) {
        LOGE("networkId is empty or too long, length %{public}zu", info.networkId.length());
        return ERR_DM_INPUT_PARA_INVALID;
    }
    if (info.deviceName.empty() || info.deviceName.length() > MAX_3RD_DEVICE_NAME_LEN) {
        LOGE("deviceName is empty or too long, length %{public}zu", info.deviceName.length());
        return ERR_DM_INPUT_PARA_INVALID;
    }
    if (static_cast<int32_t>(info.extendParam.size()) > MAX_3RD_EXTEND_PARAM_NUM) {
        LOGE("extendParam size exceed limit, size %{public}zu", info.extendParam.size());
        return ERR_DM_INPUT_PARA_INVALID;
    }
    for (const auto &item : info.extendParam) {
        if (item.first.empty() || item.first.length() > MAX_3RD_EXTEND_PARAM_LEN ||
            item.second.length() > MAX_3RD_EXTEND_PARAM_LEN) {
            LOGE("extendParam key or value is invalid");
            return ERR_DM_INPUT_PARA_INVALID;
        }
        if (IsReservedKey(item.first)) {
            LOGE("extendParam key is reserved");
            return ERR_DM_INPUT_PARA_INVALID;
        }
    }
    return DM_OK;
}

bool Dm3rdDeviceCache::IsReservedKey(const std::string &key) const
{
    return key == PARAM_KEY_OS_TYPE || key == PARAM_KEY_OS_VERSION || key == PARAM_KEY_CUSTOM_DATA ||
        key == PARAM_KEY_SYMBOL_NAME || key == PARAM_KEY_DEVICE_SOURCE || key == PARAM_KEY_CONN_ADDR_TYPE ||
        key == PARAM_KEY_BR_MAC || key == PARAM_KEY_BLE_MAC || key == PARAM_KEY_WIFI_IP ||
        key == PARAM_KEY_WIFI_PORT;
}

int32_t Dm3rdDeviceCache::Register3rdDevice(const Dm3rdDeviceInfo &info, uint32_t tokenId)
{
    int32_t ret = CheckInputParam(info);
    if (ret != DM_OK) {
        return ret;
    }
    std::lock_guard<ffrt::mutex> lock(cacheMutex_);
    auto it = thirdDeviceCache_.find(info.networkId);
    if (it != thirdDeviceCache_.end()) {
        it->second.deviceName = info.deviceName;
        it->second.extendParam = info.extendParam;
        it->second.registerTokenId = tokenId;
        LOGI("overwrite 3rd device info, networkId %{public}s", GetAnonyString(info.networkId).c_str());
        return DM_OK;
    }
    if (static_cast<int32_t>(thirdDeviceCache_.size()) >= MAX_3RD_DEVICE_CACHE_SIZE) {
        LOGE("3rd device cache is full, size %{public}zu", thirdDeviceCache_.size());
        return ERR_DM_3RD_DEVICE_CACHE_FULL;
    }
    Dm3rdCacheEntry entry;
    entry.deviceName = info.deviceName;
    entry.extendParam = info.extendParam;
    entry.registerTokenId = tokenId;
    thirdDeviceCache_[info.networkId] = entry;
    LOGI("register 3rd device info, networkId %{public}s", GetAnonyString(info.networkId).c_str());
    return DM_OK;
}

int32_t Dm3rdDeviceCache::UnRegister3rdDevice(const std::string &networkId, uint32_t tokenId)
{
    if (networkId.empty()) {
        LOGE("networkId is empty");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    std::lock_guard<ffrt::mutex> lock(cacheMutex_);
    auto it = thirdDeviceCache_.find(networkId);
    if (it == thirdDeviceCache_.end()) {
        LOGE("3rd device info not exist, networkId %{public}s", GetAnonyString(networkId).c_str());
        return ERR_DM_INPUT_PARA_INVALID;
    }
    if (it->second.registerTokenId != tokenId) {
        LOGE("tokenId mismatch, networkId %{public}s", GetAnonyString(networkId).c_str());
        return ERR_DM_NO_PERMISSION;
    }
    thirdDeviceCache_.erase(it);
    LOGI("unregister 3rd device info, networkId %{public}s", GetAnonyString(networkId).c_str());
    return DM_OK;
}

bool Dm3rdDeviceCache::Get3rdDeviceInfo(const std::string &networkId, DmDeviceInfo &info)
{
    if (networkId.empty()) {
        LOGE("networkId is empty");
        return false;
    }
    std::lock_guard<ffrt::mutex> lock(cacheMutex_);
    auto it = thirdDeviceCache_.find(networkId);
    if (it == thirdDeviceCache_.end()) {
        LOGI("3rd device info not exist, networkId %{public}s", GetAnonyString(networkId).c_str());
        return false;
    }
    const Dm3rdCacheEntry &entry = it->second;
    if (memset_s(&info, sizeof(DmDeviceInfo), 0, sizeof(DmDeviceInfo)) != DM_OK) {
        LOGE("memset_s failed");
        return false;
    }
    if (memcpy_s(info.networkId, sizeof(info.networkId), networkId.c_str(),
        std::min(sizeof(info.networkId) - 1, networkId.length())) != DM_OK) {
        LOGE("copy networkId failed");
        return false;
    }
    if (memcpy_s(info.deviceName, sizeof(info.deviceName), entry.deviceName.c_str(),
        std::min(sizeof(info.deviceName) - 1, entry.deviceName.length())) != DM_OK) {
        LOGE("copy deviceName failed");
        return false;
    }
    JsonObject extraJson;
    auto symbolIt = entry.extendParam.find(SYMBOL_NAME_MAP_KEY);
    if (symbolIt != entry.extendParam.end()) {
        extraJson[PARAM_KEY_SYMBOL_NAME] = symbolIt->second;
    }
    extraJson[PARAM_KEY_DEVICE_SOURCE] = DM_3RD_DEVICE_SOURCE;
    for (const auto &item : entry.extendParam) {
        if (item.first == SYMBOL_NAME_MAP_KEY) {
            continue;
        }
        extraJson[item.first] = item.second;
    }
    info.extraData = ToString(extraJson);
    LOGI("get 3rd device info, networkId %{public}s", GetAnonyString(networkId).c_str());
    return true;
}

void Dm3rdDeviceCache::OnStandardDeviceOnline(const std::string &networkId)
{
    if (networkId.empty()) {
        return;
    }
    std::lock_guard<ffrt::mutex> lock(cacheMutex_);
    auto it = thirdDeviceCache_.find(networkId);
    if (it == thirdDeviceCache_.end()) {
        return;
    }
    thirdDeviceCache_.erase(it);
    LOGW("standard device online, evict 3rd device info, networkId %{public}s",
        GetAnonyString(networkId).c_str());
}

void Dm3rdDeviceCache::DeleteAll3rdDeviceInfo()
{
    std::lock_guard<ffrt::mutex> lock(cacheMutex_);
    thirdDeviceCache_.clear();
    LOGI("clear all 3rd device info");
}
} // namespace DistributedHardware
} // namespace OHOS
