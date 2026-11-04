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

#include "screenlock_mini_sdk.h"

#include "dm_log.h"
#include "mini_sdk_ipc_utils.h"

namespace {
constexpr int32_t SCREENLOCK_SA_ID = 3704; // SCREENLOCK_SERVICE_ID
// ScreenLockServerIpcInterfaceCode::IS_SCREEN_LOCKED
constexpr uint32_t SCREENLOCK_CMD_IS_SCREEN_LOCKED = 0;
const std::u16string SCREENLOCK_DESCRIPTOR = u"ohos.screenlock.ScreenLockManagerInterface";
}

bool IsScreenLocked(void)
{
#if defined(SUPPORT_SCREENLOCK)
    auto remote = OHOS::DistributedHardware::MiniSdk::GetSaRemote(SCREENLOCK_SA_ID);
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    if (remote == nullptr || !OHOS::DistributedHardware::MiniSdk::WriteSaToken(data, SCREENLOCK_DESCRIPTOR) ||
        !OHOS::DistributedHardware::MiniSdk::SendSaRequest(remote, SCREENLOCK_CMD_IS_SCREEN_LOCKED, data, reply)) {
        LOGW("screenlock sa not ready or request failed, degrade to unlocked.");
        return false;
    }
    bool locked = false;
    return reply.ReadBool(locked) && locked;
#else
    return false;
#endif
}
