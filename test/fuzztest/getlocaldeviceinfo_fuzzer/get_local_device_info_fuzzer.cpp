/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "get_local_device_info_fuzzer.h"

#include "device_manager_impl.h"

namespace OHOS {
namespace DistributedHardware {

void GetLocalDeviceInfoFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::string pkgName(reinterpret_cast<const char*>(data), size);
    std::string networkId(reinterpret_cast<const char*>(data), size);
    int32_t deviceTypeId = *(reinterpret_cast<const int32_t*>(data));
    DeviceManagerImpl::GetInstance().GetLocalDeviceNetWorkId(pkgName, networkId);
    DeviceManagerImpl::GetInstance().GetLocalDeviceId(pkgName, networkId);
    DeviceManagerImpl::GetInstance().GetLocalDeviceType(pkgName, deviceTypeId);
    DeviceManagerImpl::GetInstance().GetLocalDeviceName(pkgName, networkId);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::GetLocalDeviceInfoFuzzTest(data, size);

    return 0;
}
