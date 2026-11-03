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

#include "UTTest_dm_mini_sdk_abi.h"

#include <dlfcn.h>

#include "bt_mini_sdk.h"
#include "power_mini_sdk.h"
#include "screenlock_mini_sdk.h"
#include "wifi_mini_sdk.h"

namespace OHOS {
namespace DistributedHardware {
void DmMiniSdkAbiTest::SetUp()
{
}

void DmMiniSdkAbiTest::TearDown()
{
}

void DmMiniSdkAbiTest::SetUpTestCase()
{
}

void DmMiniSdkAbiTest::TearDownTestCase()
{
}

/**
 * @tc.name: BtMiniSdkAbi_001
 * @tc.desc: libbt_mini_sdk.so exports IsBleEnabled and it is callable
 * @tc.type: FUNC
 * @tc.require: issue 2599
 */
HWTEST_F(DmMiniSdkAbiTest, BtMiniSdkAbi_001, testing::ext::TestSize.Level1)
{
    void *handle = dlopen(LIB_BT_MINI_SDK_NAME, RTLD_NOW);
    ASSERT_NE(handle, nullptr);
    auto isBleEnabled = reinterpret_cast<bool (*)(void)>(dlsym(handle, "IsBleEnabled"));
    ASSERT_NE(isBleEnabled, nullptr);
    (void)isBleEnabled();
    ASSERT_EQ(dlclose(handle), 0);
}

/**
 * @tc.name: WifiMiniSdkAbi_001
 * @tc.desc: libwifi_mini_sdk.so exports IsWifiActive and it is callable
 * @tc.type: FUNC
 * @tc.require: issue 2599
 */
HWTEST_F(DmMiniSdkAbiTest, WifiMiniSdkAbi_001, testing::ext::TestSize.Level1)
{
    void *handle = dlopen(LIB_WIFI_MINI_SDK_NAME, RTLD_NOW);
    ASSERT_NE(handle, nullptr);
    auto isWifiActive = reinterpret_cast<bool (*)(void)>(dlsym(handle, "IsWifiActive"));
    ASSERT_NE(isWifiActive, nullptr);
    (void)isWifiActive();
    ASSERT_EQ(dlclose(handle), 0);
}

/**
 * @tc.name: PowerMiniSdkAbi_001
 * @tc.desc: libpower_mini_sdk.so exports IsScreenOn and it is callable
 * @tc.type: FUNC
 * @tc.require: issue 2599
 */
HWTEST_F(DmMiniSdkAbiTest, PowerMiniSdkAbi_001, testing::ext::TestSize.Level1)
{
    void *handle = dlopen(LIB_POWER_MINI_SDK_NAME, RTLD_NOW);
    ASSERT_NE(handle, nullptr);
    auto isScreenOn = reinterpret_cast<bool (*)(void)>(dlsym(handle, "IsScreenOn"));
    ASSERT_NE(isScreenOn, nullptr);
    (void)isScreenOn();
    ASSERT_EQ(dlclose(handle), 0);
}

/**
 * @tc.name: PowerMiniSdkAbi_002
 * @tc.desc: libpower_mini_sdk.so exports WakeupDevice symbol
 * @tc.type: FUNC
 * @tc.require: issue 2599
 */
HWTEST_F(DmMiniSdkAbiTest, PowerMiniSdkAbi_002, testing::ext::TestSize.Level1)
{
    void *handle = dlopen(LIB_POWER_MINI_SDK_NAME, RTLD_NOW);
    ASSERT_NE(handle, nullptr);
    auto wakeupDevice = reinterpret_cast<int32_t (*)(int32_t)>(dlsym(handle, "WakeupDevice"));
    ASSERT_NE(wakeupDevice, nullptr);
    ASSERT_EQ(dlclose(handle), 0);
}

/**
 * @tc.name: ScreenlockMiniSdkAbi_001
 * @tc.desc: libscreenlock_mini_sdk.so exports IsScreenLocked and it is callable
 * @tc.type: FUNC
 * @tc.require: issue 2599
 */
HWTEST_F(DmMiniSdkAbiTest, ScreenlockMiniSdkAbi_001, testing::ext::TestSize.Level1)
{
    void *handle = dlopen(LIB_SCREENLOCK_MINI_SDK_NAME, RTLD_NOW);
    ASSERT_NE(handle, nullptr);
    auto isScreenLocked = reinterpret_cast<bool (*)(void)>(dlsym(handle, "IsScreenLocked"));
    ASSERT_NE(isScreenLocked, nullptr);
    (void)isScreenLocked();
    ASSERT_EQ(dlclose(handle), 0);
}
} // namespace DistributedHardware
} // namespace OHOS
