/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "distributed_device_profile_client_mock.h"

#include "gtest/gtest.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(DistributedDeviceProfileClient);
int32_t DistributedDeviceProfileClient::GetAccessControlProfile(std::map<std::string, std::string> params,
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    return DpDistributedDeviceProfileClient::dpDistributedDeviceProfileClient->GetAccessControlProfile(params,
        accessControlProfiles);
}

int32_t DistributedDeviceProfileClient::PutAccessControlProfile(const AccessControlProfile& accessControlProfile)
{
    return DpDistributedDeviceProfileClient::dpDistributedDeviceProfileClient->PutAccessControlProfile(
        accessControlProfile);
}

int32_t DistributedDeviceProfileClient::GetAllAccessControlProfile(
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    return DpDistributedDeviceProfileClient::dpDistributedDeviceProfileClient->GetAllAccessControlProfile(
        accessControlProfiles);
}

int32_t DistributedDeviceProfileClient::SubscribeDeviceProfileInited(int32_t saId, sptr<IDpInitedCallback> initedCb)
{
    return DpDistributedDeviceProfileClient::dpDistributedDeviceProfileClient->SubscribeDeviceProfileInited(saId,
        initedCb);
}

int32_t DistributedDeviceProfileClient::UnSubscribeDeviceProfileInited(int32_t saId)
{
    return DpDistributedDeviceProfileClient::dpDistributedDeviceProfileClient->UnSubscribeDeviceProfileInited(saId);
}

int32_t DistributedDeviceProfileClient::PutAllTrustedDevices(
    const std::vector<DistributedDeviceProfile::TrustedDeviceInfo> &deviceInfos)
{
    return DpDistributedDeviceProfileClient::dpDistributedDeviceProfileClient->PutAllTrustedDevices(deviceInfos);
}
} // namespace DistributedHardware
} // namespace OHOS