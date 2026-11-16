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

#ifndef OHOS_I_DM_3RD_DEVICE_CACHE_H
#define OHOS_I_DM_3RD_DEVICE_CACHE_H

#include <cstdint>
#include <string>

#include "dm_device_info.h"

namespace OHOS {
namespace DistributedHardware {
class IDm3rdDeviceCache {
public:
    virtual ~IDm3rdDeviceCache() = default;

    /**
     * @brief Register or overwrite 3rd device info in memory cache.
     * @param info 3rd device info, networkId and deviceName are required.
     * @param tokenId caller tokenId from IPC context.
     * @return Returns 0 if success.
     */
    virtual int32_t Register3rdDevice(const Dm3rdDeviceInfo &info, uint32_t tokenId) = 0;

    /**
     * @brief UnRegister 3rd device info, only the registrant tokenId can unregister.
     * @param networkId 3rd device networkId.
     * @param tokenId caller tokenId from IPC context.
     * @return Returns 0 if success.
     */
    virtual int32_t UnRegister3rdDevice(const std::string &networkId, uint32_t tokenId) = 0;

    /**
     * @brief Get 3rd device info by networkId, fill DmDeviceInfo with extraData json.
     * @param networkId 3rd device networkId.
     * @param info output device info.
     * @return Returns true if found.
     */
    virtual bool Get3rdDeviceInfo(const std::string &networkId, DmDeviceInfo &info) = 0;

    /**
     * @brief Evict 3rd device info when a standard device with same networkId is online.
     * @param networkId standard device networkId.
     */
    virtual void OnStandardDeviceOnline(const std::string &networkId) = 0;

    /**
     * @brief Clear all 3rd device info, only for test or reset.
     */
    virtual void DeleteAll3rdDeviceInfo() = 0;
};

using CreateDM3rdDeviceCacheFuncPtr = IDm3rdDeviceCache *(*)(void);
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_I_DM_3RD_DEVICE_CACHE_H
