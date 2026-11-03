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

#ifndef OHOS_DM_SCREENLOCK_MINI_SDK_H
#define OHOS_DM_SCREENLOCK_MINI_SDK_H

#ifndef __cplusplus
#include <stdbool.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define LIB_SCREENLOCK_MINI_SDK_NAME "libscreenlock_mini_sdk.z.so"

/*
 * Query the screen lock state of the device. The adapter talks to the
 * screenlock SA directly over IPC (same protocol as the official proxy)
 * without linking the full screenlock sdk client library.
 * Returns true only when the screenlock SA is ready and the screen
 * is locked; uses the official client's GetSystemAbility lookup and returns
 * false when the screenlock part is cut, the lookup fails or the reply is
 * invalid. The mini sdk is a device_manager private dependency (inner api),
 * only the device_manager component is allowed to load it.
 */
bool IsScreenLocked(void);

#ifdef __cplusplus
}
#endif

#endif // OHOS_DM_SCREENLOCK_MINI_SDK_H
