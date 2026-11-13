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
#include "i_dm_3rd_device_cache.h"

namespace OHOS {
namespace DistributedHardware {
struct Dm3rdCacheEntry {
    std::string deviceName;
    uint16_t deviceType = 0;
    std::map<std::string, std::string> extendParam;
    uint32_t registerTokenId = 0;
};

class Dm3rdDeviceCache : public IDm3rdDeviceCache {
    DM_DECLARE_SINGLE_INSTANCE(Dm3rdDeviceCache);

public:
    int32_t Register3rdDevice(const Dm3rdDeviceInfo &info, uint32_t tokenId) override;
    int32_t UnRegister3rdDevice(const std::string &networkId, uint32_t tokenId) override;
    bool Get3rdDeviceInfo(const std::string &networkId, DmDeviceInfo &info) override;
    void OnStandardDeviceOnline(const std::string &networkId) override;
    void DeleteAll3rdDeviceInfo() override;

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
