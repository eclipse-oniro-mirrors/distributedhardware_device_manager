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
#ifndef OHOS_DM_MINI_SDK_SA_MOCK_H
#define OHOS_DM_MINI_SDK_SA_MOCK_H

// Force-included only by the protocol test target. The parcel and adapter
// implementations stay unchanged; only system-ability lookup is substituted.
#include "mini_sdk_ipc_utils.h"
namespace OHOS::DistributedHardware::MiniSdk {
sptr<IRemoteObject> GetSaRemoteForTest(int32_t saId);
sptr<IRemoteObject> GetSaRemoteWithWaitForTest(int32_t saId);
} // namespace OHOS::DistributedHardware::MiniSdk
#define GetSaRemote GetSaRemoteForTest
#define GetSaRemoteWithWait GetSaRemoteWithWaitForTest
#endif // OHOS_DM_MINI_SDK_SA_MOCK_H
