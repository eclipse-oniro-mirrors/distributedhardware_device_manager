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

#include "ivi_screen_power_helper.h"

#include <memory>
#include <unordered_map>

#include "dm_error_type.h"
#include "ffrt.h"
#include "power_mgr_client.h"

#if defined(CAR_DEVICE_ENABLE) && defined(VEHICLE_POWER_ENABLE)
#include "ivi_powersrv_manager.h"
#endif

namespace OHOS {
namespace DistributedHardware {

namespace {
const std::string CONTROL_PANEL_TAG = "control_panel";
const std::string REAR_ARMREST_PANEL_TAG = "rear_armrest_panel";
const std::string CO_DRIVER_PANEL_TAG = "co_driver_panel";
const std::string CAR_HEAD_LIGHT_PANEL_TAG = "car_head_light_panel";
const std::string INTERACTIVE_MINI_PANEL_TAG = "interactive_mini_panel";

const std::unordered_map<int32_t, std::string> &DisplayIdToTagMap()
{
    static const std::unordered_map<int32_t, std::string> map = {
        { 0, CONTROL_PANEL_TAG },
        { 4, REAR_ARMREST_PANEL_TAG },
        { 6, CO_DRIVER_PANEL_TAG },
        { 7, CAR_HEAD_LIGHT_PANEL_TAG },
        { 9, INTERACTIVE_MINI_PANEL_TAG },
    };
    return map;
}
} // namespace

#if defined(CAR_DEVICE_ENABLE) && defined(VEHICLE_POWER_ENABLE)
constexpr int32_t SCREEN_OFF_SIGNAL = 1;

class IviScreenStateCallback : public OHOS::IviPowerSrv::IviPowerSrvSignalCallback {
public:
    explicit IviScreenStateCallback(int32_t displayId) : displayId_(displayId) {}
    ~IviScreenStateCallback() override = default;

    void OnChangeSignal(int32_t value) override
    {
        LOGI("OnChangeSignal, displayId: %{public}d, value: %{public}d", displayId_, value);
        if (value == SCREEN_OFF_SIGNAL) {
            int32_t id = displayId_;
            ffrt::submit([id]() {
                if (!IviScreenPowerHelper::GetInstance().IsMonitorActive()) {
                    LOGI("monitor inactive, skip wakeUp, displayId: %{public}d", id);
                    return;
                }
                int32_t ret = IviScreenPowerHelper::GetInstance().WakeUpByDisplayId(id);
                if (ret != DM_OK) {
                    LOGE("WakeUpByDisplayId fail, displayId: %{public}d, ret: %{public}d", id, ret);
                }
            });
        }
    }

private:
    int32_t displayId_;
};
#endif

IviScreenPowerHelper &IviScreenPowerHelper::GetInstance()
{
    static IviScreenPowerHelper instance;
    return instance;
}

std::string IviScreenPowerHelper::DisplayIdToScreenTag(int32_t displayId)
{
    const auto &map = DisplayIdToTagMap();
    auto it = map.find(displayId);
    if (it != map.end()) {
        return it->second;
    }
    LOGW("displayId=%{public}d screen tag not configured, mapping needs car screen tags", displayId);
    return "";
}

bool IviScreenPowerHelper::IsScreenOnByDisplayId(int32_t displayId)
{
#if defined(CAR_DEVICE_ENABLE) && defined(VEHICLE_POWER_ENABLE)
    std::string tag = DisplayIdToScreenTag(displayId);
    if (tag.empty()) {
        return false;
    }
    std::shared_ptr<OHOS::IviPowerSrv::IviPowerSrvManager> powerSrvMgr =
        OHOS::IviPowerSrv::IviPowerSrvManager::GetInstance();
    CHECK_NULL_RETURN(powerSrvMgr, false);
    bool isScreenOn = false;
    int32_t ret = powerSrvMgr->IsScreenOn(tag, isScreenOn);
    if (ret != 0) {
        LOGE("IsScreenOn fail, displayId=%{public}d ret=%{public}d", displayId, ret);
        return false;
    }
    return isScreenOn;
#else
    (void)displayId;
    return false;
#endif
}

int32_t IviScreenPowerHelper::WakeUpByDisplayId(int32_t displayId)
{
#if defined(CAR_DEVICE_ENABLE) && defined(VEHICLE_POWER_ENABLE)
    std::string tag = DisplayIdToScreenTag(displayId);
    if (tag.empty()) {
        LOGE("WakeUp fail, displayId=%{public}d screen tag not configured", displayId);
        return ERR_DM_FAILED;
    }
    std::shared_ptr<OHOS::IviPowerSrv::IviPowerSrvManager> powerSrvMgr =
        OHOS::IviPowerSrv::IviPowerSrvManager::GetInstance();
    CHECK_NULL_RETURN(powerSrvMgr, ERR_DM_FAILED);
    int32_t ret = powerSrvMgr->WakeUp(tag);
    if (ret != 0) {
        LOGE("WakeUp fail, displayId=%{public}d ret=%{public}d", displayId, ret);
        return ERR_DM_FAILED;
    }
    LOGI("WakeUp success, displayId=%{public}d", displayId);
    return DM_OK;
#else
    (void)displayId;
    return DM_OK;
#endif
}

IviScreenPowerHelper::~IviScreenPowerHelper()
{
#if defined(CAR_DEVICE_ENABLE) && defined(VEHICLE_POWER_ENABLE)
    std::lock_guard<std::mutex> lock(stateMutex_);
    monitorActive_ = false;
    screenStateCallback_.reset();
    subscribedTag_.clear();
#endif
}

int32_t IviScreenPowerHelper::SubscribeScreenState(int32_t displayId)
{
#if defined(CAR_DEVICE_ENABLE) && defined(VEHICLE_POWER_ENABLE)
    std::string tag = DisplayIdToScreenTag(displayId);
    if (tag.empty()) {
        LOGE("SubscribeScreenState fail, displayId=%{public}d screen tag not configured", displayId);
        return ERR_DM_FAILED;
    }
    std::lock_guard<std::mutex> lock(stateMutex_);
    UnsubscribeScreenStateLocked();
    auto callback = std::make_shared<IviScreenStateCallback>(displayId);
    std::shared_ptr<OHOS::IviPowerSrv::IviPowerSrvManager> powerSrvMgr =
        OHOS::IviPowerSrv::IviPowerSrvManager::GetInstance();
    CHECK_NULL_RETURN(powerSrvMgr, ERR_DM_FAILED);
    int32_t ret = powerSrvMgr->SubscribeScreenState(tag, callback);
    if (ret != 0) {
        LOGE("SubscribeScreenState fail, displayId=%{public}d ret=%{public}d", displayId, ret);
        return ERR_DM_FAILED;
    }
    subscribedTag_ = tag;
    screenStateCallback_ = callback;
    monitorActive_ = true;
    LOGI("SubscribeScreenState success, displayId=%{public}d", displayId);
    return DM_OK;
#else
    (void)displayId;
    return DM_OK;
#endif
}

void IviScreenPowerHelper::UnsubscribeScreenState()
{
#if defined(CAR_DEVICE_ENABLE) && defined(VEHICLE_POWER_ENABLE)
    std::lock_guard<std::mutex> lock(stateMutex_);
    UnsubscribeScreenStateLocked();
#endif
}

void IviScreenPowerHelper::UnsubscribeScreenStateLocked()
{
#if defined(CAR_DEVICE_ENABLE) && defined(VEHICLE_POWER_ENABLE)
    monitorActive_ = false;
    if (screenStateCallback_ == nullptr) {
        return;
    }
    if (!subscribedTag_.empty()) {
        std::shared_ptr<OHOS::IviPowerSrv::IviPowerSrvManager> powerSrvMgr =
            OHOS::IviPowerSrv::IviPowerSrvManager::GetInstance();
        if (powerSrvMgr != nullptr) {
            int32_t ret = powerSrvMgr->UnsubscribeScreenState(subscribedTag_);
            if (ret != 0) {
                LOGE("UnsubscribeScreenState fail, ret=%{public}d", ret);
            }
        }
    }
    screenStateCallback_.reset();
    subscribedTag_.clear();
    LOGI("UnsubscribeScreenState done");
#endif
}

} // namespace DistributedHardware
} // namespace OHOS
