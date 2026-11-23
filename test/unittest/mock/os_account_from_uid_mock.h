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
#ifndef OHOS_DM_OS_ACCOUNT_FROM_UID_MOCK_H
#define OHOS_DM_OS_ACCOUNT_FROM_UID_MOCK_H

#include <gmock/gmock.h>

#include "os_account_manager.h"

namespace OHOS {
namespace DistributedHardware {
class IOsAccountFromUidManager {
public:
    IOsAccountFromUidManager() = default;
    virtual ~IOsAccountFromUidManager() = default;

    virtual ErrCode GetOsAccountLocalIdFromUid(const int uid, int &localId) = 0;
    static std::shared_ptr<IOsAccountFromUidManager> GetOrCreateOsAccountFromUidManager();
    static void ReleaseOsAccountFromUidManager();

private:
    static std::shared_ptr<IOsAccountFromUidManager> fromUidManager_;
};

class OsAccountFromUidMock : public IOsAccountFromUidManager {
public:
    OsAccountFromUidMock() = default;
    ~OsAccountFromUidMock() override = default;

    MOCK_METHOD(ErrCode, GetOsAccountLocalIdFromUid, (const int, int &));
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_OS_ACCOUNT_FROM_UID_MOCK_H
