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

#ifndef OHOS_DM_POWER_MINI_SDK_H
#define OHOS_DM_POWER_MINI_SDK_H

#if defined(__cplusplus)
#include <cstdint>
#else
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define LIB_POWER_MINI_SDK_NAME "libpower_mini_sdk.z.so"

/*
 * Query the screen on/off state of the device. The adapter talks to the
 * power SA directly over IPC (same protocol as the official proxy)
 * without linking the full power sdk client library.
 * Returns true only when the power SA is ready and the screen is on;
 * degrades to false when the power part is cut or the SA is not ready.
 * The mini sdk is a device_manager private dependency (inner api), only
 * the device_manager component is allowed to load it.
 */
bool IsScreenOn(void);

/*
 * Wake up the device for the given reason.
 * The reason is a power WakeupDeviceType enum value, for example
 * WAKEUP_DEVICE_END_DREAM(33) used by the end-dream auth scenario.
 * Returns the power PowerErrors enum value (ERR_OK = 0); returns
 * ERR_CONNECTION_FAIL(4900101) when the power part is cut or the request
 * fails.
 */
int32_t WakeupDevice(int32_t reason);

#ifdef __cplusplus
}
#endif

#endif // OHOS_DM_POWER_MINI_SDK_H
