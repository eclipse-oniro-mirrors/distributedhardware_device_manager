/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstddef>
#include <cstdint>
#include <string>

#include "device_manager_impl.h"
#include "device_manager.h"
#include "device_manager_callback.h"
#include "device_discovery_fuzzer.h"

namespace OHOS {
namespace DistributedHardware {
class DeviceDiscoveryCallbackTest : public DiscoveryCallback {
public:
    DeviceDiscoveryCallbackTest() : DiscoveryCallback() {}
    virtual ~DeviceDiscoveryCallbackTest() {}
    virtual void OnDiscoverySuccess(uint16_t subscribeId) override {}
    virtual void OnDiscoveryFailed(uint16_t subscribeId, int32_t failedReason) override {}
    virtual void OnDeviceFound(uint16_t subscribeId, const DmDeviceInfo &deviceInfo) override {}
};

void DeviceDiscoveryFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }
    std::string bundleName(reinterpret_cast<const char*>(data), size);

    DmSubscribeInfo subInfo;
    subInfo.subscribeId = *(reinterpret_cast<const uint16_t*>(data));
    subInfo.mode = *(reinterpret_cast<const DmDiscoverMode*>(data));
    subInfo.medium = *(reinterpret_cast<const DmExchangeMedium*>(data));
    subInfo.freq = *(reinterpret_cast<const DmExchangeFreq*>(data));
    subInfo.isSameAccount = *(reinterpret_cast<const bool*>(data));
    subInfo.isWakeRemote = *(reinterpret_cast<const bool*>(data));
    strncpy_s(subInfo.capability, DM_MAX_DEVICE_CAPABILITY_LEN, (char*)data, DM_MAX_DEVICE_CAPABILITY_LEN);
    std::string extra(reinterpret_cast<const char*>(data), size);
    int16_t subscribeId = *(reinterpret_cast<const int16_t*>(data));

    std::shared_ptr<DiscoveryCallback> callback = std::make_shared<DeviceDiscoveryCallbackTest>();
    int32_t ret = DeviceManager::GetInstance().StartDeviceDiscovery(bundleName,
        subInfo, extra, callback);
    ret = DeviceManager::GetInstance().StopDeviceDiscovery(bundleName, subscribeId);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DeviceDiscoveryFuzzTest(data, size);
    return 0;
}
