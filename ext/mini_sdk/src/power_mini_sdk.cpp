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

#include "power_mini_sdk.h"

#include "dm_log.h"
#include "mini_sdk_ipc_utils.h"

namespace {
constexpr int32_t POWER_MANAGER_SA_ID = 3301; // POWER_MANAGER_SERVICE_ID
// IPowerMgrIpcCode::COMMAND_IS_SCREEN_ON_IPC / COMMAND_WAKEUP_DEVICE_IPC
constexpr uint32_t POWER_CMD_IS_SCREEN_ON = 23;
constexpr uint32_t POWER_CMD_WAKEUP_DEVICE = 17;
constexpr int32_t POWER_ERR_OK = 0;
// PowerErrors::ERR_CONNECTION_FAIL, aligned with PowerMgrClient failure mapping.
constexpr int32_t POWER_ERR_CONNECTION_FAIL = 4900101;
const std::u16string POWER_MGR_DESCRIPTOR = u"OHOS.PowerMgr.IPowerMgr";
const std::u16string WAKEUP_DETAIL = u"end_dream";
}

bool IsScreenOn(void)
{
#if defined(SUPPORT_POWER_MANAGER)
    auto remote = OHOS::DistributedHardware::MiniSdk::GetSaRemote(POWER_MANAGER_SA_ID);
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    if (remote == nullptr || !OHOS::DistributedHardware::MiniSdk::WriteSaToken(data, POWER_MGR_DESCRIPTOR) ||
        !data.WriteInt32(0) || // needPrintLog=false; the full SDK defaults to true.
        !OHOS::DistributedHardware::MiniSdk::SendSaRequest(remote, POWER_CMD_IS_SCREEN_ON, data, reply)) {
        LOGW("power sa not ready or request failed, degrade to screen off.");
        return false;
    }
    int32_t errCode = 0;
    if (!reply.ReadInt32(errCode) || errCode != POWER_ERR_OK) {
        LOGW("query screen state failed, errCode: %{public}d.", errCode);
        return false;
    }
    int32_t screenOn = 0;
    return reply.ReadInt32(screenOn) && screenOn == 1;
#else
    return false;
#endif
}

int32_t WakeupDevice(int32_t reason)
{
#if defined(SUPPORT_POWER_MANAGER)
    auto remote = OHOS::DistributedHardware::MiniSdk::GetSaRemote(POWER_MANAGER_SA_ID);
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    if (remote == nullptr || !OHOS::DistributedHardware::MiniSdk::WriteSaToken(data, POWER_MGR_DESCRIPTOR) ||
        !data.WriteInt64(OHOS::DistributedHardware::MiniSdk::GetTickCountMs()) || !data.WriteInt32(reason) ||
        !data.WriteString16(WAKEUP_DETAIL) ||
        !OHOS::DistributedHardware::MiniSdk::SendSaRequest(remote, POWER_CMD_WAKEUP_DEVICE, data, reply)) {
        LOGW("power sa not ready or request failed, wakeup failed.");
        return POWER_ERR_CONNECTION_FAIL;
    }
    int32_t errCode = 0;
    if (!reply.ReadInt32(errCode) || errCode != POWER_ERR_OK) {
        LOGW("wakeup failed, errCode: %{public}d.", errCode);
        return POWER_ERR_CONNECTION_FAIL;
    }
    int32_t powerError = POWER_ERR_CONNECTION_FAIL;
    return reply.ReadInt32(powerError) ? powerError : POWER_ERR_CONNECTION_FAIL;
#else
    return POWER_ERR_CONNECTION_FAIL;
#endif
}
