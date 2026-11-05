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

#ifndef DM_UI_API_H
#define DM_UI_API_H

#include <stddef.h>
#include <stdint.h>

enum DmUiOperation {
    DM_UI_CONFIRM = 0,
    DM_UI_SERVICE_CONFIRM,
    DM_UI_PIN,
    DM_UI_INPUT,
    DM_UI_CLOSE,
};

/* Input is borrowed for the duration of Invoke. The module owns all async state. */
struct DmUiApi {
    uint32_t version;
    uint32_t size;
    int32_t (*invoke)(uint32_t operation, const char *data, size_t size);
};
constexpr uint32_t DM_UI_API_VERSION = 1;
using DmGetUiApi = const DmUiApi *(*)();

extern "C" __attribute__((visibility("default"))) const DmUiApi *DmGetUiApiV1();

constexpr uint32_t DM_UI_SESSION_API_VERSION = 2;
constexpr uint32_t DM_UI_CAN_UNLOAD_DIALOG = 1;
// AbilityManager ConnectionRecord::CompleteDisconnect(ERR_OK, ..., true)
// reports target termination as ERR_OK - 1 after removing its connection.
constexpr int32_t DM_UI_TARGET_TERMINATED = -1;

struct DmUiSessionHost {
    uint32_t size;
    uint64_t generation;
    // Request retirement only. The host destroys the context after all calls return.
    void (*retire)(uint64_t generation);
    // The resident host owns the task and its execution lease, including queue time.
    int32_t (*submit)(uint64_t generation, void (*work)(void *), void *context);
};

/* Private same-platform ABI. No STL ownership crosses this boundary.
 * connection is a borrowed public OHOS::AAFwk::IAbilityConnection interface;
 * remote is a borrowed public OHOS::IRemoteObject interface. The host keeps a
 * strong reference throughout each call. Neither address denotes a private class.
 */
struct DmUiSessionApi {
    uint32_t version;
    uint32_t size;
    uint32_t flags;
    void *(*create)(const DmUiSessionHost *host, void *connection);
    int32_t (*invoke)(void *context, uint32_t operation, const char *data, size_t size);
    void (*connected)(void *context, void *remote, int32_t result);
    void (*disconnected)(void *context, int32_t result);
    void (*destroy)(void *context);
};

using DmGetUiSessionApi = const DmUiSessionApi *(*)();
extern "C" __attribute__((visibility("default"))) const DmUiSessionApi *DmGetUiSessionApiV2();

#endif
