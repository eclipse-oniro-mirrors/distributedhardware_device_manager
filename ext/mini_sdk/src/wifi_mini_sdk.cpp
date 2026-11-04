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

#include "wifi_mini_sdk.h"

#include "dm_log.h"
#include "mini_sdk_ipc_utils.h"

namespace {
constexpr int32_t WIFI_DEVICE_SA_ID = 1120; // WIFI_DEVICE_SYS_ABILITY_ID
constexpr uint32_t WIFI_CMD_GET_DEVICE_SERVICE = 0;
constexpr int32_t WIFI_DEFAULT_INSTANCE = 0;
// DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_ACTIVE
constexpr uint32_t WIFI_CMD_IS_WIFI_ACTIVE = 0x1013;
constexpr int32_t WIFI_OPT_SUCCESS = 0;
const std::u16string WIFI_DEVICE_DESCRIPTOR = u"ohos.wifi.IWifiDeviceService";
const std::u16string WIFI_MANAGER_DESCRIPTOR = u"ohos.wifi.IWifiDeviceMgr";

#if defined(SUPPORT_WIFI)
OHOS::sptr<OHOS::IRemoteObject> GetWifiDeviceRemote()
{
    auto manager = OHOS::DistributedHardware::MiniSdk::GetSaRemote(WIFI_DEVICE_SA_ID);
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    if (manager == nullptr || !OHOS::DistributedHardware::MiniSdk::WriteSaToken(data, WIFI_MANAGER_DESCRIPTOR) ||
        !data.WriteInt32(WIFI_DEFAULT_INSTANCE) ||
        !OHOS::DistributedHardware::MiniSdk::SendSaRequest(manager, WIFI_CMD_GET_DEVICE_SERVICE, data, reply)) {
        return nullptr;
    }
    return reply.ReadRemoteObject();
}
#endif
}

bool IsWifiActive(void)
{
#if defined(SUPPORT_WIFI)
    auto remote = GetWifiDeviceRemote();
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    if (remote == nullptr || !OHOS::DistributedHardware::MiniSdk::WriteSaToken(data, WIFI_DEVICE_DESCRIPTOR) ||
        !data.WriteInt32(0) || // placeholder, same as WifiDeviceProxy
        !OHOS::DistributedHardware::MiniSdk::SendSaRequest(remote, WIFI_CMD_IS_WIFI_ACTIVE, data, reply)) {
        LOGW("wifi sa not ready or request failed, degrade to disabled.");
        return false;
    }
    int32_t exception = 0;
    int32_t ret = 0;
    if (!reply.ReadInt32(exception) || exception != 0 || !reply.ReadInt32(ret) || ret != WIFI_OPT_SUCCESS) {
        LOGW("query wifi state failed, exception: %{public}d, ret: %{public}d.", exception, ret);
        return false;
    }
    bool active = false;
    return reply.ReadBool(active) && active;
#else
    return false;
#endif
}
