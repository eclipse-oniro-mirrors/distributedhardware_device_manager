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

#include "notify_event_fuzzer.h"

#include "device_manager_impl.h"

namespace OHOS {
namespace DistributedHardware {

void NotifyEventFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::string pkgName(reinterpret_cast<const char*>(data), size);
    int32_t eventId = *(reinterpret_cast<const int32_t*>(data));
    std::string event(reinterpret_cast<const char*>(data), size);
    DeviceManagerImpl::GetInstance().NotifyEvent(pkgName, eventId, event);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::NotifyEventFuzzTest(data, size);

    return 0;
}
