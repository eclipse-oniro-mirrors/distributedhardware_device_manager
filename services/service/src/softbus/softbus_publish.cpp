/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "softbus_publish.h"

#include <mutex>

#ifdef SUPPORT_BLUETOOTH
#include "bluetooth_def.h"
#endif // SUPPORT_BLUETOOTH
#include "dm_constants.h"
#include "dm_device_info.h"
#include "dm_log.h"
#include "dm_softbus_cache.h"
#include "system_ability_definition.h"
#ifdef SUPPORT_WIFI
#include "wifi_msg.h"
#endif // SUPPORT_WIFI

namespace OHOS {
namespace DistributedHardware {

static IPublishCb softbusPublishCallback_ = {
    .OnPublishResult = SoftbusPublish::OnSoftbusPublishResult,
};

std::mutex g_publishMutex;

void PublishCommonEventCallback(int32_t bluetoothState, int32_t wifiState, int32_t screenState)
{
    LOGI("start, bleState: %{public}d, wifiState: %{public}d, screenState: %{public}d",
        bluetoothState, wifiState, screenState);
    std::lock_guard<std::mutex> saLock(g_publishMutex);
    DmDeviceInfo info;
    SoftbusCache::GetInstance().GetLocalDeviceInfo(info);
    if (info.deviceTypeId == DmDeviceType::DEVICE_TYPE_WATCH) {
        LOGE("deviceType: %{public}d is watch, not publish", static_cast<int32_t>(info.deviceTypeId));
        return;
    }
    SoftbusPublish softbusPublish;
    if (screenState == DM_SCREEN_OFF) {
        int32_t ret = softbusPublish.StopPublishSoftbusLNN(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
        if (ret != DM_OK) {
            LOGE("stop publish failed, ret : %{public}d.", ret);
            return;
        }
        LOGI("stop publish successed, ret : %{public}d.", ret);
        return;
    }
#ifdef SUPPORT_BLUETOOTH
    if (bluetoothState == static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURN_ON) &&
        screenState == DM_SCREEN_ON) {
        softbusPublish.StopPublishSoftbusLNN(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
        int32_t ret = softbusPublish.PublishSoftbusLNN();
        if (ret != DM_OK) {
            LOGE("bluetooth publish failed, ret : %{public}d.", ret);
            return;
        }
        LOGI("bluetooth publish successed, ret : %{public}d.", ret);
        return;
    }
    softbusPublish.StopPublishSoftbusLNN(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
#endif // SUPPORT_BLUETOOTH

#ifdef SUPPORT_WIFI
    if (wifiState == static_cast<int32_t>(OHOS::Wifi::WifiState::ENABLED) &&
        screenState == DM_SCREEN_ON) {
        softbusPublish.StopPublishSoftbusLNN(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
        int32_t ret = softbusPublish.PublishSoftbusLNN();
        if (ret != DM_OK) {
            LOGE("wifi publish failed, ret : %{public}d.", ret);
            return;
        }
        LOGI("wifi publish successed, ret : %{public}d.", ret);
        return;
    }
    softbusPublish.StopPublishSoftbusLNN(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
#endif // SUPPORT_WIFI
}

SoftbusPublish::SoftbusPublish()
{
}

SoftbusPublish::~SoftbusPublish()
{
}

void SoftbusPublish::OnSoftbusPublishResult(int publishId, PublishResult result)
{
    LOGD("publishId: %{public}d, result: %{public}d.", publishId, result);
}

int32_t SoftbusPublish::PublishSoftbusLNN()
{
    PublishInfo publishInfo;
    publishInfo.publishId = DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID;
    publishInfo.mode = DiscoverMode::DISCOVER_MODE_PASSIVE;
    publishInfo.medium = ExchangeMedium::AUTO;
    publishInfo.freq = ExchangeFreq::LOW;
    publishInfo.capability = DM_CAPABILITY_OSD;
    publishInfo.ranging = false;

    LOGI("Begin");
    int32_t ret = PublishLNN(DM_PKG_NAME, &publishInfo, &softbusPublishCallback_);
    if (ret != DM_OK) {
        LOGE("[SOFTBUS]PublishLNN failed, ret: %{public}d.", ret);
        return ERR_DM_PUBLISH_FAILED;
    }
    return DM_OK;
}

int32_t SoftbusPublish::StopPublishSoftbusLNN(int32_t publishId)
{
    LOGI("Begin, publishId: %{public}d.", publishId);
    int32_t ret = StopPublishLNN(DM_PKG_NAME, publishId);
    if (ret != DM_OK) {
        LOGE("[SOFTBUS]StopPublishLNN failed, ret: %{public}d.", ret);
        return ERR_DM_STOP_PUBLISH_LNN_FAILED;
    }
    return DM_OK;
}
} // namespace DistributedHardware
} // namespace OHOS