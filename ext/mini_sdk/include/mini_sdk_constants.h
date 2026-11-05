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

#ifndef OHOS_DM_MINI_SDK_CONSTANTS_H
#define OHOS_DM_MINI_SDK_CONSTANTS_H

#include <cstdint>

namespace OHOS::DistributedHardware::MiniSdk {
// Bluetooth::BTStateID in bluetooth_def.h: common-event values, not
// BluetoothState query values.
constexpr int32_t BT_EVENT_STATE_ON = 1;
constexpr int32_t BT_EVENT_STATE_OFF = 3;

// OHOS::Wifi::WifiState in wifi_msg.h: common-event values, not IsWifiActive's
// bool result.
constexpr int32_t WIFI_STATE_ENABLED = 3;
constexpr int32_t WIFI_STATE_DISABLED = 1;

// PowerMgr::WakeupDeviceType in power_state_machine_info.h and PowerErrors in
// power_errors.h.
constexpr int32_t POWER_WAKEUP_END_DREAM = 33;
constexpr int32_t POWER_ERR_OK = 0;
constexpr int32_t POWER_ERR_CONNECTION_FAIL = 4900101;

// UTTest_dm_mini_sdk_protocol compares these private constants with the
// official SDK definitions.
} // namespace OHOS::DistributedHardware::MiniSdk

#endif // OHOS_DM_MINI_SDK_CONSTANTS_H
