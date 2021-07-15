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

#ifndef OHOS_DEVICE_MANAGER_SUBSCRIBE_INFO_H
#define OHOS_DEVICE_MANAGER_SUBSCRIBE_INFO_H

#include "parcel.h"

namespace OHOS {
namespace DistributedHardware {
enum DmDiscoverMode : int32_t {
    /* Passive */
    DISCOVER_MODE_PASSIVE = 0x55,
    /* Proactive */
    DISCOVER_MODE_ACTIVE  = 0xAA
};

enum DmExchangeMedium : int32_t {
    /** Automatic medium selection */
    AUTO = 0,
    /** Bluetooth */
    BLE = 1,
    /** Wi-Fi */
    COAP = 2,
    /** USB */
    USB = 3,
    MEDIUM_BUTT
};

/**
 * @brief Enumerates frequencies for publishing services.
 *
 * This enumeration applies only to Bluetooth and is not supported currently.
 */
enum DmExchangeFreq : int32_t {
    /** Low */
    LOW = 0,
    /** Medium */
    MID = 1,
    /** High */
    HIGH = 2,
    /** Super-high */
    SUPER_HIGH = 3,
    FREQ_BUTT
};

const std::string DM_CAPABILITY_DDMP = "ddmpCapability";

struct DmSubscribeInfo : public Parcelable {
    /** Service ID */
    uint16_t subscribeId;
    /** Discovery mode for service subscription. For details, see {@link DmDiscoverMode}. */
    DmDiscoverMode mode;
    /** Service subscription medium. For details, see {@link DmExchangeMedium}. */
    DmExchangeMedium medium;
    /** Service subscription frequency. For details, see {@link DmExchangeFreq}. */
    DmExchangeFreq freq;
    /** only find the device with the same account */
    bool isSameAccount;
    /** find the sleeping devices */
    bool isWakeRemote;
    /** Service subscription capability. */
    std::string capability;
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static DmSubscribeInfo *Unmarshalling(Parcel &parcel);
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DEVICE_MANAGER_SUBSCRIBE_INFO_H
