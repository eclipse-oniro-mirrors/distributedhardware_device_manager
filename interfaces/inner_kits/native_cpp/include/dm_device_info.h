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

#ifndef OHOS_DEVICE_MANAGER_DEVICE_INFO_H
#define OHOS_DEVICE_MANAGER_DEVICE_INFO_H

#include "parcel.h"

namespace OHOS {
namespace DistributedHardware {
enum DMDeviceType : uint8_t {
    DEVICE_TYPE_UNKNOWN = 0x00,
    DEVICE_TYPE_WIFI_CAMERA = 0x08,
    DEVICE_TYPE_AUDIO = 0x0A,
    DEVICE_TYPE_PC = 0x0C,
    DEVICE_TYPE_PHONE = 0x0E,
    DEVICE_TYPE_PAD = 0x11,
    DEVICE_TYPE_WATCH = 0x6D,
    DEVICE_TYPE_CAR = 0x83,
    DEVICE_TYPE_TV = 0x9C,
};

enum DmDeviceState : uint8_t {
    DEVICE_STATE_UNKNOWN = 0,
    DEVICE_STATE_ONLINE = 1,
    DEVICE_STATE_OFFLINE = 2,
};

struct DmDeviceInfo : public Parcelable {
    std::string deviceId;
    std::string deviceName;
    DMDeviceType deviceTypeId;
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static DmDeviceInfo *Unmarshalling(Parcel &parcel);
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DEVICE_MANAGER_DEVICE_INFO_H
