/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "dm_device_info.h"

namespace OHOS {
namespace DistributedHardware {
bool DmDeviceInfo::ReadFromParcel(Parcel &parcel)
{
    deviceId = parcel.ReadString();
    deviceName = parcel.ReadString();
    deviceTypeId = (DMDeviceType)parcel.ReadUint8();
    return true;
}

DmDeviceInfo *DmDeviceInfo::Unmarshalling(Parcel &parcel)
{
    DmDeviceInfo *info = new (std::nothrow) DmDeviceInfo();
    if (info == nullptr) {
        return nullptr;
    }

    if (!info->ReadFromParcel(parcel)) {
        delete info;
        info = nullptr;
    }
    return info;
}

bool DmDeviceInfo::Marshalling(Parcel &parcel) const
{
    parcel.WriteString(deviceId);
    parcel.WriteString(deviceName);
    parcel.WriteUint8((uint8_t)deviceTypeId);
    return true;
}
} // namespace DistributedHardware
} // namespace OHOS
