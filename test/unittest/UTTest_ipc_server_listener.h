/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_SERVER_LISTENER_TEST_H
#define OHOS_IPC_SERVER_LISTENER_TEST_H

#include <gtest/gtest.h>

#include "ipc_client_stub.h"
#include "ipc_server_stub.h"
#include "ipc_server_listener.h"

namespace OHOS {
namespace DistributedHardware {
class IpcServerListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
} // namespace DistributedHardware
} // namespace OHOS

#endif //  OHOS_IPC_SERVER_CLIENT_PROXY_TEST_H
