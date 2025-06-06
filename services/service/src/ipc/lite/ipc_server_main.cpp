/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <unistd.h>

#include "dm_constants.h"
#include "dm_log.h"
#include "device_manager_service.h"
#include "ipc_server_stub.h"

using namespace OHOS::DistributedHardware;

static void InitAll()
{
    const int32_t dmServiceInitDelay = 5;
    sleep(dmServiceInitDelay);
    if (IpcServerStubInit() != DM_OK) {
        LOGE("IpcServerStubInit failed.");
        return;
    }
    if (DeviceManagerService::GetInstance().Init() != DM_OK) {
        LOGE("service init failed.");
        return;
    }
    LOGI("DM service init success.");
}

int32_t main(int32_t argc, char *argv[])
{
    LOGI("DM service init start.");
    (void)argc;
    (void)argv;
    InitAll();
    while (true) {
        pause();
    }
    return 0;
}
