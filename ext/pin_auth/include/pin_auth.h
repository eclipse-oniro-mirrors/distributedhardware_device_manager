/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_DM_PIN_AUTH_H
#define OHOS_DM_PIN_AUTH_H

#include <cstdint>
#include <memory>

#include "authentication.h"
#include "dm_auth_manager.h"
#include "dm_ability_manager.h"
#include "pin_auth_ui.h"

namespace OHOS {
namespace DistributedHardware {
class PinAuth : public IAuthentication {
public:
    PinAuth();
    ~PinAuth() override;

    /**
     * @tc.name: PinAuth::ShowAuthInfo
     * @tc.desc: ShowAuthInfo of the PinAuth
     * @tc.type: FUNC
     */
    int32_t ShowAuthInfo(std::string &authToken, std::shared_ptr<DmAuthManager> authManager) override;

    /**
     * @tc.name: PinAuth::StartAuth
     * @tc.desc: Star tAuth of the PinAuth
     * @tc.type: FUNC
     */
    int32_t StartAuth(std::string &authToken, std::shared_ptr<DmAuthManager> authManager) override;

private:
    std::shared_ptr<PinAuthUi> pinAuthUi_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_PIN_AUTH_H
