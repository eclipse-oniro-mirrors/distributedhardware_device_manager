/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "UTTest_ivi_screen_power_helper.h"

#include "dm_error_type.h"

namespace OHOS {
namespace DistributedHardware {
void IviScreenPowerHelperTest::SetUpTestCase() {}
void IviScreenPowerHelperTest::TearDownTestCase() {}
void IviScreenPowerHelperTest::SetUp() {}
void IviScreenPowerHelperTest::TearDown() {}

HWTEST_F(IviScreenPowerHelperTest, DisplayIdToScreenTag_001, testing::ext::TestSize.Level1)
{
    auto &helper = IviScreenPowerHelper::GetInstance();
    EXPECT_EQ(helper.DisplayIdToScreenTag(0), std::string("control_panel"));
}

HWTEST_F(IviScreenPowerHelperTest, DisplayIdToScreenTag_002, testing::ext::TestSize.Level1)
{
    auto &helper = IviScreenPowerHelper::GetInstance();
    EXPECT_TRUE(helper.DisplayIdToScreenTag(999).empty());
}

HWTEST_F(IviScreenPowerHelperTest, DisplayIdToScreenTag_003, testing::ext::TestSize.Level1)
{
    auto &helper = IviScreenPowerHelper::GetInstance();
    EXPECT_EQ(helper.DisplayIdToScreenTag(4), std::string("rear_armrest_panel"));
}

HWTEST_F(IviScreenPowerHelperTest, DisplayIdToScreenTag_004, testing::ext::TestSize.Level1)
{
    auto &helper = IviScreenPowerHelper::GetInstance();
    EXPECT_EQ(helper.DisplayIdToScreenTag(6), std::string("co_driver_panel"));
}

HWTEST_F(IviScreenPowerHelperTest, DisplayIdToScreenTag_005, testing::ext::TestSize.Level1)
{
    auto &helper = IviScreenPowerHelper::GetInstance();
    EXPECT_EQ(helper.DisplayIdToScreenTag(7), std::string("car_head_light_panel"));
}

HWTEST_F(IviScreenPowerHelperTest, DisplayIdToScreenTag_006, testing::ext::TestSize.Level1)
{
    auto &helper = IviScreenPowerHelper::GetInstance();
    EXPECT_EQ(helper.DisplayIdToScreenTag(9), std::string("interactive_mini_panel"));
}

HWTEST_F(IviScreenPowerHelperTest, MockIsScreenOn_001, testing::ext::TestSize.Level1)
{
    IviScreenPowerHelperMock mock;
    mock.SetIsOn(true);
    EXPECT_TRUE(mock.IsScreenOnByDisplayId(0));
    mock.SetIsOn(false);
    EXPECT_FALSE(mock.IsScreenOnByDisplayId(0));
}

HWTEST_F(IviScreenPowerHelperTest, MockWakeUp_001, testing::ext::TestSize.Level1)
{
    IviScreenPowerHelperMock mock;
    EXPECT_EQ(mock.GetWakeCallCount(), 0);
    EXPECT_EQ(mock.WakeUpByDisplayId(0), DM_OK);
    mock.SetWakeRet(ERR_DM_FAILED);
    EXPECT_EQ(mock.WakeUpByDisplayId(0), ERR_DM_FAILED);
    EXPECT_EQ(mock.GetWakeCallCount(), 2);
}

HWTEST_F(IviScreenPowerHelperTest, IsScreenOnByDisplayId_001, testing::ext::TestSize.Level1)
{
    auto &helper = IviScreenPowerHelper::GetInstance();
    EXPECT_FALSE(helper.IsScreenOnByDisplayId(0));
}

HWTEST_F(IviScreenPowerHelperTest, WakeUpByDisplayId_001, testing::ext::TestSize.Level1)
{
    auto &helper = IviScreenPowerHelper::GetInstance();
    EXPECT_EQ(helper.WakeUpByDisplayId(0), DM_OK);
}

HWTEST_F(IviScreenPowerHelperTest, SubscribeUnsubscribe_001, testing::ext::TestSize.Level1)
{
    auto &helper = IviScreenPowerHelper::GetInstance();
    EXPECT_EQ(helper.SubscribeScreenState(0), DM_OK);
    helper.UnsubscribeScreenState();
}

HWTEST_F(IviScreenPowerHelperTest, UnsubscribeWithoutSubscribe_001, testing::ext::TestSize.Level1)
{
    auto &helper = IviScreenPowerHelper::GetInstance();
    helper.UnsubscribeScreenState();
}

HWTEST_F(IviScreenPowerHelperTest, DoubleSubscribeNoDeadlock_001, testing::ext::TestSize.Level1)
{
    auto &helper = IviScreenPowerHelper::GetInstance();
    EXPECT_EQ(helper.SubscribeScreenState(0), DM_OK);
    EXPECT_EQ(helper.SubscribeScreenState(4), DM_OK);
    helper.UnsubscribeScreenState();
}
} // namespace DistributedHardware
} // namespace OHOS
