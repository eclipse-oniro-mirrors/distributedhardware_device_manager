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

#ifndef OHOS_DM_MINI_SDK_IPC_UTILS_H
#define OHOS_DM_MINI_SDK_IPC_UTILS_H

#include <chrono>
#include <cstdint>
#include <string>
#include "iremote_object.h"
#include "iservice_registry.h"
#include "message_option.h"
#include "message_parcel.h"

namespace OHOS {
namespace DistributedHardware {
namespace MiniSdk {
/*
 * Internal helpers shared by the mini sdk adapters. Each adapter talks to its
 * target system ability directly over IPC without linking the full third
 * party sdk client library, so only ipc and samgr are needed as dependencies.
 */

// Probe whether the target system ability has been published and get its remote object.
inline sptr<IRemoteObject> GetSaRemote(int32_t saId)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return nullptr;
    }
    return samgr->CheckSystemAbility(saId);
}

// Write the target interface descriptor, the same token check as the official proxy.
inline bool WriteSaToken(MessageParcel &data, const std::u16string &descriptor)
{
    return data.WriteInterfaceToken(descriptor);
}

// Synchronous IPC request to the target sa remote. Returns false when the
// remote is invalid or the request fails.
inline bool SendSaRequest(const sptr<IRemoteObject> &remote, uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    if (remote == nullptr) {
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    return remote->SendRequest(code, data, reply, option) == 0;
}

// Monotonic milliseconds since boot, used as the call time of wake up calls.
inline int64_t GetTickCountMs()
{
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}
} // namespace MiniSdk
} // namespace DistributedHardware
} // namespace OHOS

#endif // OHOS_DM_MINI_SDK_IPC_UTILS_H
