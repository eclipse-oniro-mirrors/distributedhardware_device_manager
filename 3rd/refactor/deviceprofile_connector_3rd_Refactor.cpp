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
#include <cstdio>

#include "deviceprofile_connector_3rd_Refactor.h"
#include "dm_anonymous_3rd.h"
#include "dm_constants_3rd.h"
#include "dm_crypto_3rd.h"
#include "dm_error_type_3rd.h"
#include "dm_log_3rd.h"
#include "multiple_user_connector_3rd.h"
#include "distributed_device_profile_client.h"
#include "system_ability_definition.h"
#include "ipc_skeleton.h"

using namespace OHOS::DistributedDeviceProfile;

namespace OHOS {
namespace DistributedHardware {

namespace {
constexpr uint32_t MAX_SESSION_KEY_LENGTH = 512;
}

IMPLEMENT_SINGLE_INSTANCE(DeviceProfileConnector3rdRefactor);

int32_t DeviceProfileConnector3rdRefactor::PutSessionKey(int32_t userId,
    const std::vector<unsigned char> &sessionKeyArray, int32_t &sessionKeyId)
{
    if (sessionKeyArray.empty()) {
        LOGE("SessionKey array is empty.");
        return ERR_DM_FAILED;
    }
    if (sessionKeyArray.size() > MAX_SESSION_KEY_LENGTH) {
        LOGE("SessionKey size invalid, too large.");
        return ERR_DM_FAILED;
    }
    int32_t ret = DistributedDeviceProfileClient::GetInstance().PutSessionKey(
        static_cast<uint32_t>(userId), sessionKeyArray, sessionKeyId);
    if (ret != DM_OK) {
        LOGE("PutSessionKey failed: %{public}d", ret);
        return ret;
    }
    return DM_OK;
}

int32_t DeviceProfileConnector3rdRefactor::DeleteSessionKey(int32_t userId, int32_t sessionKeyId)
{
    int32_t ret = DistributedDeviceProfileClient::GetInstance().DeleteSessionKey(
        static_cast<uint32_t>(userId), sessionKeyId);
    if (ret != DM_OK) {
        LOGE("DeleteSessionKey failed: %{public}d", ret);
        return ret;
    }
    return DM_OK;
}

int32_t DeviceProfileConnector3rdRefactor::GetSessionKey(int32_t userId, int32_t sessionKeyId,
    std::vector<unsigned char> &sessionKeyArray)
{
    int32_t ret = DistributedDeviceProfileClient::GetInstance().GetSessionKey(
        static_cast<uint32_t>(userId), sessionKeyId, sessionKeyArray);
    if (ret != DM_OK) {
        LOGE("GetSessionKey failed: %{public}d", ret);
        return ret;
    }
    return DM_OK;
}

IDeviceProfileConnectorRefactor *CreateDpConnectorRefactorInstance()
{
    return &DeviceProfileConnector3rdRefactor::GetInstance();
}

} // namespace DistributedHardware
} // namespace OHOS
