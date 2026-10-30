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

#include "UTTest_dm_3rd_device_cache.h"

#include "dm_error_type.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void Dm3rdDeviceCacheTest::SetUpTestCase() {}
void Dm3rdDeviceCacheTest::TearDownTestCase() {}
void Dm3rdDeviceCacheTest::SetUp()
{
    Dm3rdDeviceCache::GetInstance().DeleteAll3rdDeviceInfo();
}
void Dm3rdDeviceCacheTest::TearDown() {}

Dm3rdDeviceInfo Build3rdDeviceInfo(const std::string &networkId, const std::string &deviceName)
{
    Dm3rdDeviceInfo info;
    info.networkId = networkId;
    info.deviceName = deviceName;
    return info;
}

/**
 * @tc.name: Register3rdDevice_001
 * @tc.desc: register valid 3rd device info success
 * @tc.type: FUNC
 */
HWTEST_F(Dm3rdDeviceCacheTest, Register3rdDevice_001, testing::ext::TestSize.Level1)
{
    Dm3rdDeviceInfo info = Build3rdDeviceInfo("networkId_001", "deviceName_001");
    int32_t ret = Dm3rdDeviceCache::GetInstance().Register3rdDevice(info, 1);
    EXPECT_EQ(ret, DM_OK);
    DmDeviceInfo deviceInfo;
    bool isFound = Dm3rdDeviceCache::GetInstance().Get3rdDeviceInfo(info.networkId, deviceInfo);
    EXPECT_TRUE(isFound);
    EXPECT_EQ(std::string(deviceInfo.networkId), info.networkId);
    EXPECT_EQ(std::string(deviceInfo.deviceName), info.deviceName);
}

/**
 * @tc.name: Register3rdDevice_002
 * @tc.desc: register with empty or too long networkId or deviceName
 * @tc.type: FUNC
 */
HWTEST_F(Dm3rdDeviceCacheTest, Register3rdDevice_002, testing::ext::TestSize.Level1)
{
    Dm3rdDeviceInfo info = Build3rdDeviceInfo("", "deviceName_002");
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(info, 1), ERR_DM_INPUT_PARA_INVALID);

    info = Build3rdDeviceInfo("networkId_002", "");
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(info, 1), ERR_DM_INPUT_PARA_INVALID);

    info = Build3rdDeviceInfo(std::string(97, 'a'), "deviceName_002");
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(info, 1), ERR_DM_INPUT_PARA_INVALID);

    info = Build3rdDeviceInfo("networkId_002", std::string(129, 'a'));
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(info, 1), ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: Register3rdDevice_003
 * @tc.desc: register with invalid extend param
 * @tc.type: FUNC
 */
HWTEST_F(Dm3rdDeviceCacheTest, Register3rdDevice_003, testing::ext::TestSize.Level1)
{
    Dm3rdDeviceInfo info = Build3rdDeviceInfo("networkId_003", "deviceName_003");
    info.extendParam["OS_TYPE"] = "1";
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(info, 1), ERR_DM_INPUT_PARA_INVALID);

    info.extendParam.clear();
    info.extendParam["SYMBOL_NAME"] = "symbol";
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(info, 1), ERR_DM_INPUT_PARA_INVALID);

    info.extendParam.clear();
    info.extendParam["DEVICE_SOURCE"] = "3RD";
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(info, 1), ERR_DM_INPUT_PARA_INVALID);

    info.extendParam.clear();
    info.extendParam["CUSTOM_DATA"] = "data";
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(info, 1), ERR_DM_INPUT_PARA_INVALID);

    info.extendParam.clear();
    info.extendParam[std::string(129, 'k')] = "value";
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(info, 1), ERR_DM_INPUT_PARA_INVALID);

    info.extendParam.clear();
    for (int32_t i = 0; i < 21; ++i) {
        info.extendParam["key_" + std::to_string(i)] = "value";
    }
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(info, 1), ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: Register3rdDevice_004
 * @tc.desc: overwrite registered 3rd device info, ownership transferred to new tokenId
 * @tc.type: FUNC
 */
HWTEST_F(Dm3rdDeviceCacheTest, Register3rdDevice_004, testing::ext::TestSize.Level1)
{
    Dm3rdDeviceInfo info = Build3rdDeviceInfo("networkId_004", "deviceName_old");
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(info, 1), DM_OK);

    Dm3rdDeviceInfo newInfo = Build3rdDeviceInfo("networkId_004", "deviceName_new");
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(newInfo, 2), DM_OK);

    DmDeviceInfo deviceInfo;
    EXPECT_TRUE(Dm3rdDeviceCache::GetInstance().Get3rdDeviceInfo("networkId_004", deviceInfo));
    EXPECT_EQ(std::string(deviceInfo.deviceName), "deviceName_new");
    // ownership transferred: old tokenId can not unregister
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().UnRegister3rdDevice("networkId_004", 1), ERR_DM_NO_PERMISSION);
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().UnRegister3rdDevice("networkId_004", 2), DM_OK);
}

/**
 * @tc.name: Register3rdDevice_005
 * @tc.desc: cache capacity limit is 100, overwrite is allowed when full
 * @tc.type: FUNC
 */
HWTEST_F(Dm3rdDeviceCacheTest, Register3rdDevice_005, testing::ext::TestSize.Level1)
{
    for (int32_t i = 0; i < 100; ++i) {
        Dm3rdDeviceInfo info = Build3rdDeviceInfo("networkId_cap_" + std::to_string(i), "deviceName");
        EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(info, 1), DM_OK);
    }
    Dm3rdDeviceInfo newInfo = Build3rdDeviceInfo("networkId_cap_100", "deviceName");
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(newInfo, 1), ERR_DM_3RD_DEVICE_CACHE_FULL);

    // overwrite existing entry is allowed even if cache is full
    Dm3rdDeviceInfo overwriteInfo = Build3rdDeviceInfo("networkId_cap_0", "deviceName_overwrite");
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(overwriteInfo, 1), DM_OK);

    // unregister then register new entry success
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().UnRegister3rdDevice("networkId_cap_99", 1), DM_OK);
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(newInfo, 1), DM_OK);
}

/**
 * @tc.name: UnRegister3rdDevice_001
 * @tc.desc: unregister with mismatched or invalid params
 * @tc.type: FUNC
 */
HWTEST_F(Dm3rdDeviceCacheTest, UnRegister3rdDevice_001, testing::ext::TestSize.Level1)
{
    Dm3rdDeviceInfo info = Build3rdDeviceInfo("networkId_unreg_001", "deviceName");
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(info, 1), DM_OK);

    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().UnRegister3rdDevice("networkId_unreg_001", 2),
        ERR_DM_NO_PERMISSION);
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().UnRegister3rdDevice("networkId_not_exist", 1),
        ERR_DM_INPUT_PARA_INVALID);
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().UnRegister3rdDevice("", 1), ERR_DM_INPUT_PARA_INVALID);

    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().UnRegister3rdDevice("networkId_unreg_001", 1), DM_OK);
    DmDeviceInfo deviceInfo;
    EXPECT_FALSE(Dm3rdDeviceCache::GetInstance().Get3rdDeviceInfo("networkId_unreg_001", deviceInfo));
}

/**
 * @tc.name: Get3rdDeviceInfo_001
 * @tc.desc: get 3rd device info with extraData json contains SYMBOL_NAME and DEVICE_SOURCE
 * @tc.type: FUNC
 */
HWTEST_F(Dm3rdDeviceCacheTest, Get3rdDeviceInfo_001, testing::ext::TestSize.Level1)
{
    Dm3rdDeviceInfo info = Build3rdDeviceInfo("networkId_get_001", "deviceName_get");
    info.extendParam["symbolName"] = "mySymbol";
    info.extendParam["customKey"] = "customValue";
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(info, 1), DM_OK);

    DmDeviceInfo deviceInfo;
    EXPECT_TRUE(Dm3rdDeviceCache::GetInstance().Get3rdDeviceInfo("networkId_get_001", deviceInfo));
    EXPECT_NE(deviceInfo.extraData.find("\"SYMBOL_NAME\":\"mySymbol\""), std::string::npos);
    EXPECT_NE(deviceInfo.extraData.find("\"DEVICE_SOURCE\":\"3RD\""), std::string::npos);
    EXPECT_NE(deviceInfo.extraData.find("\"customKey\":\"customValue\""), std::string::npos);
    EXPECT_EQ(std::string(deviceInfo.deviceId), "");
    EXPECT_EQ(deviceInfo.deviceTypeId, DEVICE_TYPE_UNKNOWN);

    EXPECT_FALSE(Dm3rdDeviceCache::GetInstance().Get3rdDeviceInfo("networkId_not_exist", deviceInfo));
    EXPECT_FALSE(Dm3rdDeviceCache::GetInstance().Get3rdDeviceInfo("", deviceInfo));
}

/**
 * @tc.name: OnStandardDeviceOnline_001
 * @tc.desc: evict 3rd device info when standard device with same networkId is online
 * @tc.type: FUNC
 */
HWTEST_F(Dm3rdDeviceCacheTest, OnStandardDeviceOnline_001, testing::ext::TestSize.Level1)
{
    Dm3rdDeviceInfo info = Build3rdDeviceInfo("networkId_online_001", "deviceName");
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(info, 1), DM_OK);

    Dm3rdDeviceCache::GetInstance().OnStandardDeviceOnline("networkId_online_001");
    DmDeviceInfo deviceInfo;
    EXPECT_FALSE(Dm3rdDeviceCache::GetInstance().Get3rdDeviceInfo("networkId_online_001", deviceInfo));

    // evict non-exist or empty networkId has no side effect
    Dm3rdDeviceCache::GetInstance().OnStandardDeviceOnline("networkId_not_exist");
    Dm3rdDeviceCache::GetInstance().OnStandardDeviceOnline("");
}

/**
 * @tc.name: DeleteAll3rdDeviceInfo_001
 * @tc.desc: clear all 3rd device info
 * @tc.type: FUNC
 */
HWTEST_F(Dm3rdDeviceCacheTest, DeleteAll3rdDeviceInfo_001, testing::ext::TestSize.Level1)
{
    Dm3rdDeviceInfo info = Build3rdDeviceInfo("networkId_clear_001", "deviceName");
    EXPECT_EQ(Dm3rdDeviceCache::GetInstance().Register3rdDevice(info, 1), DM_OK);
    Dm3rdDeviceCache::GetInstance().DeleteAll3rdDeviceInfo();
    DmDeviceInfo deviceInfo;
    EXPECT_FALSE(Dm3rdDeviceCache::GetInstance().Get3rdDeviceInfo("networkId_clear_001", deviceInfo));
}
} // namespace DistributedHardware
} // namespace OHOS
