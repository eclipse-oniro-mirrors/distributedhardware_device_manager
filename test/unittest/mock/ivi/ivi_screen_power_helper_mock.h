/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_IVI_SCREEN_POWER_HELPER_MOCK_H
#define OHOS_IVI_SCREEN_POWER_HELPER_MOCK_H

#include <cstdint>
#include <string>

#include "dm_error_type.h"
#include "ivi_screen_power_helper.h"

namespace OHOS {
namespace DistributedHardware {

class IviScreenPowerHelperMock : public IviScreenPowerHelper {
public:
    std::string DisplayIdToScreenTag(int32_t displayId) override
    {
        return tag_;
    }

    bool IsScreenOnByDisplayId(int32_t displayId) override
    {
        return isOn_;
    }

    int32_t WakeUpByDisplayId(int32_t displayId) override
    {
        ++wakeCallCount_;
        return wakeRet_;
    }

    void SetTag(const std::string &tag)
    {
        tag_ = tag;
    }

    void SetIsOn(bool isOn)
    {
        isOn_ = isOn;
    }

    void SetWakeRet(int32_t ret)
    {
        wakeRet_ = ret;
    }

    int32_t GetWakeCallCount() const
    {
        return wakeCallCount_;
    }

private:
    std::string tag_ = "control_panel";
    bool isOn_ = true;
    int32_t wakeRet_ = DM_OK;
    int32_t wakeCallCount_ = 0;
};

} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_IVI_SCREEN_POWER_HELPER_MOCK_H
