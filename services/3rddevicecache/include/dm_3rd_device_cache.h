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

#ifndef DM_3RD_DEVICE_CACHE_H
#define DM_3RD_DEVICE_CACHE_H

#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>

#include "dm_device_info.h"
#include "dm_single_instance.h"
#include "ffrt.h"

namespace OHOS {
namespace DistributedHardware {
struct Dm3rdCacheEntry {
    std::string deviceName;
    std::map<std::string, std::string> extendParam;
    uint32_t registerTokenId = 0;
};

class Dm3rdDeviceCache {
    DM_DECLARE_SINGLE_INSTANCE(Dm3rdDeviceCache);

public:
    /**
     * @brief Register or overwrite 3rd device info in memory cache.
     * @param info 3rd device info, networkId and deviceName are required.
     * @param tokenId caller tokenId from IPC context.
     * @return Returns 0 if success.
     */
    int32_t Register3rdDevice(const Dm3rdDeviceInfo &info, uint32_t tokenId);

    /**
     * @brief UnRegister 3rd device info, only the registrant tokenId can unregister.
     * @param networkId 3rd device networkId.
     * @param tokenId caller tokenId from IPC context.
     * @return Returns 0 if success.
     */
    int32_t UnRegister3rdDevice(const std::string &networkId, uint32_t tokenId);

    /**
     * @brief Get 3rd device info by networkId, fill DmDeviceInfo with extraData json.
     * @param networkId 3rd device networkId.
     * @param info output device info.
     * @return Returns true if found.
     */
    bool Get3rdDeviceInfo(const std::string &networkId, DmDeviceInfo &info);

    /**
     * @brief Evict 3rd device info when a standard device with same networkId is online.
     * @param networkId standard device networkId.
     */
    void OnStandardDeviceOnline(const std::string &networkId);

    /**
     * @brief Clear all 3rd device info, only for test or reset.
     */
    void DeleteAll3rdDeviceInfo();

private:
    int32_t CheckInputParam(const Dm3rdDeviceInfo &info) const;
    bool IsReservedKey(const std::string &key) const;

private:
    ffrt::mutex cacheMutex_;
    std::unordered_map<std::string, Dm3rdCacheEntry> thirdDeviceCache_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // DM_3RD_DEVICE_CACHE_H
