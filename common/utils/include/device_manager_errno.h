/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_DEVICE_MANAGER_ERRNO_H
#define OHOS_DEVICE_MANAGER_ERRNO_H
#include "errors.h"

namespace OHOS {
namespace DistributedHardware {
enum {
    DISTRIBUTEDHARDWARE_MODULE_DEVICEMANAGER = 0x00
};

// Error code for Common
constexpr ErrCode DEVICE_MANAGER_ERR_OFFSET = ErrCodeOffset(SUBSYS_DISTRIBUTEDHARDWARE,
    DISTRIBUTEDHARDWARE_MODULE_DEVICEMANAGER);
enum {
    ERR_DEVICEMANAGER_OPERATION_FAILED = DEVICE_MANAGER_ERR_OFFSET + 1,
    ERR_DEVICEMANAGER_SERVICE_NOT_READY = DEVICE_MANAGER_ERR_OFFSET + 2,
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DEVICE_MANAGER_LOG_H
