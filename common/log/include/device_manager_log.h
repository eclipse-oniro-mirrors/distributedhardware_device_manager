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

#ifndef OHOS_DEVICE_MANAGER_LOG_H
#define OHOS_DEVICE_MANAGER_LOG_H
#include "hilog/log.h"

namespace OHOS {
namespace DistributedHardware {
static constexpr OHOS::HiviewDFX::HiLogLabel DM_LABEL = {LOG_CORE, LOG_DOMAIN, DH_LOG_TAG};

#define PRINT_LOG(Level, fmt, ...) \
    OHOS::HiviewDFX::HiLog::Level(DM_LABEL, "[%{public}s] " fmt, __FUNCTION__, ##__VA_ARGS__)

#ifdef HILOGD
#undef HILOGD
#endif

#ifdef HILOGI
#undef HILOGI
#endif

#ifdef HILOGW
#undef HILOGW
#endif

#ifdef HILOGE
#undef HILOGE
#endif

#ifdef HILOGF
#undef HILOGF
#endif

#define HILOGD(fmt, ...) PRINT_LOG(Debug, fmt, ##__VA_ARGS__)
#define HILOGI(fmt, ...) PRINT_LOG(Info, fmt, ##__VA_ARGS__)
#define HILOGW(fmt, ...) PRINT_LOG(Warn, fmt, ##__VA_ARGS__)
#define HILOGE(fmt, ...) PRINT_LOG(Error, fmt, ##__VA_ARGS__)
#define HILOGF(fmt, ...) PRINT_LOG(Fatal, fmt, ##__VA_ARGS__)
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DEVICE_MANAGER_LOG_H
