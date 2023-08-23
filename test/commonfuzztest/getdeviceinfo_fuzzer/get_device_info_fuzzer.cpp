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

#include "get_device_info_fuzzer.h"

#include "device_manager_impl.h"

namespace OHOS {
namespace DistributedHardware {

void GetDeviceInfoFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint16_t)) || (size > DM_MAX_DEVICE_ID_LEN)) {
        return;
    }

    std::string pkgName(reinterpret_cast<const char*>(data), size);
    std::string networkId(reinterpret_cast<const char*>(data), size);
    DmDeviceInfo deviceInfo;
    deviceInfo.authForm = DmAuthForm::ACROSS_ACCOUNT;
    int32_t ret = memcpy_s(deviceInfo.deviceId, DM_MAX_DEVICE_ID_LEN, (reinterpret_cast<const char *>(data)), size);
    if (ret != EOK) {
        return;
    }
    ret = memcpy_s(deviceInfo.deviceName, DM_MAX_DEVICE_NAME_LEN, (reinterpret_cast<const char *>(data)), size);
    if (ret != EOK) {
        return;
    }

    DeviceManagerImpl::GetInstance().GetDeviceInfo(pkgName, networkId, deviceInfo);
    std::string deviceName;
    DeviceManagerImpl::GetInstance().GetDeviceName(pkgName, networkId, deviceName);
    int32_t deviceTypeId = 1;
    DeviceManagerImpl::GetInstance().GetDeviceType(pkgName, networkId, deviceTypeId);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::GetDeviceInfoFuzzTest(data, size);

    return 0;
}
