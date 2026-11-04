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

#include "bt_mini_sdk.h"

#include "dm_log.h"
#include "mini_sdk_ipc_utils.h"

namespace {
constexpr int32_t BLUETOOTH_HOST_SA_ID = 1130; // BLUETOOTH_HOST_SYS_ABILITY_ID
// BluetoothHostInterfaceCode::BT_GETSTATE
constexpr uint32_t BT_CMD_GET_STATE = 4;
// BluetoothState: STATE_TURNING_ON / STATE_ON / STATE_TURNING_OFF / STATE_BLE_ON
constexpr int32_t BT_STATE_TURNING_ON = 1;
constexpr int32_t BT_STATE_ON = 2;
constexpr int32_t BT_STATE_TURNING_OFF = 3;
constexpr int32_t BT_STATE_BLE_ON = 5;
constexpr int32_t BT_STATE_BLE_OWNER_MODE = 7;
const std::u16string BT_HOST_DESCRIPTOR = u"ohos.ipc.IBluetoothHost";
}

bool IsBleEnabled(void)
{
#if defined(SUPPORT_BLUETOOTH)
    auto remote = OHOS::DistributedHardware::MiniSdk::GetSaRemote(BLUETOOTH_HOST_SA_ID);
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    if (remote == nullptr || !OHOS::DistributedHardware::MiniSdk::WriteSaToken(data, BT_HOST_DESCRIPTOR) ||
        !OHOS::DistributedHardware::MiniSdk::SendSaRequest(remote, BT_CMD_GET_STATE, data, reply)) {
        LOGW("bluetooth sa not ready or request failed, degrade to disabled.");
        return false;
    }
    int32_t exception = 0;
    if (!reply.ReadInt32(exception) || exception != 0) {
        LOGW("get bluetooth state failed, exception: %{public}d.", exception);
        return false;
    }
    int32_t state = 0;
    if (!reply.ReadInt32(state)) {
        return false;
    }
    return state == BT_STATE_TURNING_ON || state == BT_STATE_ON || state == BT_STATE_TURNING_OFF ||
        state == BT_STATE_BLE_ON || state == BT_STATE_BLE_OWNER_MODE;
#else
    return false;
#endif
}
