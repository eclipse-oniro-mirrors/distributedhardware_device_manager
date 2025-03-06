/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_PERMISSION_MANAGER_MOCK_H
#define OHOS_PERMISSION_MANAGER_MOCK_H

#include <string>
#include <gmock/gmock.h>

#include "permission_manager.h"

namespace OHOS {
namespace DistributedHardware {
class DmPermissionManager {
public:
    virtual ~DmPermissionManager() = default;
public:
    virtual bool CheckProcessNameValidOnPinHolder(const std::string &processName) = 0;
    virtual bool CheckProcessNameValidOnAuthCode(const std::string &processName) = 0;
    virtual int32_t GetCallerProcessName(std::string &processName) = 0;
    virtual bool CheckProcessNameValidOnSetDnPolicy(const std::string &processName) = 0;
public:
    static inline std::shared_ptr<DmPermissionManager> dmPermissionManager = nullptr;
};

class PermissionManagerMock : public DmPermissionManager {
public:
    MOCK_METHOD(bool, CheckProcessNameValidOnPinHolder, (const std::string &));
    MOCK_METHOD(bool, CheckProcessNameValidOnAuthCode, (const std::string &));
    MOCK_METHOD(int32_t, GetCallerProcessName, (std::string &));
    MOCK_METHOD(bool, CheckProcessNameValidOnSetDnPolicy, (const std::string &));
};
}
}
#endif
