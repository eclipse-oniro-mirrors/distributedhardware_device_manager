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

#ifndef OHOS_IVI_SCREEN_POWER_HELPER_H
#define OHOS_IVI_SCREEN_POWER_HELPER_H

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

#include "dm_log.h"

namespace OHOS {
namespace DistributedHardware {

class IviScreenPowerHelper {
public:
    static IviScreenPowerHelper &GetInstance();
    virtual ~IviScreenPowerHelper();

    // Maps numeric displayId to IVI screen tag string.
    // Confirmed: 0=control_panel, 4=rear_armrest_panel,
    //            6=co_driver_panel, 7=car_head_light_panel,
    //            9=interactive_mini_panel.
    virtual std::string DisplayIdToScreenTag(int32_t displayId);

    // Queries whether the target binding screen is on;
    // treats query failure as screen off (conservative gating, triggers subsequent wake-up).
    virtual bool IsScreenOnByDisplayId(int32_t displayId);

    // Wake up the target binding screen;
    // returns DM_OK on success, ERR_DM_FAILED on failure/timeout (does not silently hang).
    virtual int32_t WakeUpByDisplayId(int32_t displayId);

    // Subscribe to screen state monitoring at binding start;
    // auto-wakes target screen in callback when screen turns off during binding.
    virtual int32_t SubscribeScreenState(int32_t displayId);

    // Unsubscribe screen state monitoring at binding end.
    virtual void UnsubscribeScreenState();

    bool IsMonitorActive() const { return monitorActive_.load(); }

protected:
    IviScreenPowerHelper() = default;

private:
    void UnsubscribeScreenStateLocked();
    std::mutex stateMutex_;
    std::atomic<bool> monitorActive_{false};
    std::string subscribedTag_;
    std::shared_ptr<void> screenStateCallback_;
};

} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_IVI_SCREEN_POWER_HELPER_H
