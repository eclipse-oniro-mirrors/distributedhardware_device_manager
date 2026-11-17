/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "os_account_from_uid_mock.h"

using namespace OHOS::DistributedHardware;

namespace OHOS {
namespace DistributedHardware {
std::shared_ptr<IOsAccountFromUidManager> IOsAccountFromUidManager::fromUidManager_ = nullptr;

std::shared_ptr<IOsAccountFromUidManager> IOsAccountFromUidManager::GetOrCreateOsAccountFromUidManager()
{
    if (!fromUidManager_) {
        fromUidManager_ = std::make_shared<OsAccountFromUidMock>();
    }
    return fromUidManager_;
}

void IOsAccountFromUidManager::ReleaseOsAccountFromUidManager()
{
    fromUidManager_.reset();
    fromUidManager_ = nullptr;
}
} // namespace DistributedHardware

namespace AccountSA {
ErrCode OsAccountManager::GetOsAccountLocalIdFromUid(const int uid, int &localId)
{
    return IOsAccountFromUidManager::GetOrCreateOsAccountFromUidManager()->GetOsAccountLocalIdFromUid(
        uid, localId);
}
} // namespace AccountSA
} // namespace OHOS
