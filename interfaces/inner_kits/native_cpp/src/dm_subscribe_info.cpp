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

#include "dm_subscribe_info.h"

namespace OHOS {
namespace DistributedHardware {
bool DmSubscribeInfo::ReadFromParcel(Parcel &parcel)
{
    subscribeId = parcel.ReadInt16();
    mode = (DmDiscoverMode)parcel.ReadInt32();
    medium = (DmExchangeMedium)parcel.ReadInt32();
    freq = (DmExchangeFreq)parcel.ReadInt32();
    isSameAccount = parcel.ReadBool();
    isWakeRemote = parcel.ReadBool();
    capability = parcel.ReadString();
    return true;
}

DmSubscribeInfo *DmSubscribeInfo::Unmarshalling(Parcel &parcel)
{
    DmSubscribeInfo *info = new (std::nothrow) DmSubscribeInfo();
    if (info == nullptr) {
        return nullptr;
    }

    if (!info->ReadFromParcel(parcel)) {
        delete info;
        info = nullptr;
    }
    return info;
}

bool DmSubscribeInfo::Marshalling(Parcel &parcel) const
{
    parcel.WriteInt16(subscribeId);
    parcel.WriteInt32((int32_t)mode);
    parcel.WriteInt32((int32_t)medium);
    parcel.WriteInt32((uint8_t)freq);
    parcel.WriteBool(isSameAccount);
    parcel.WriteBool(isWakeRemote);
    parcel.WriteString(capability);
    return true;
}
} // namespace DistributedHardware
} // namespace OHOS
