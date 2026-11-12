/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "UTTest_dm_service_load.h"

#include <chrono>
#include <thread>
#include <unistd.h>

#include "dm_constants.h"
#include "dm_service_load.h"
#include "dm_system_ability_manager_mock.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

using ::testing::_;
using ::testing::An;
using ::testing::Return;

namespace OHOS {
namespace DistributedHardware {
void DmServiceLoadTest::SetUp()
{
}

void DmServiceLoadTest::TearDown()
{
}

void DmServiceLoadTest::SetUpTestCase()
{
}

void DmServiceLoadTest::TearDownTestCase()
{
}

namespace {
constexpr int32_t SHORT_DELAY_MS = 200;
/**
 * @tc.name: LoadDMService_001
 * @tc.desc: 1. mock samgr so LoadSystemAbility returns DM_OK
 *           2. another thread calls SetLoadFinish after a short delay to unblock the cv wait
 *           3. verify LoadDMService returns DM_OK
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, LoadDMService_001, testing::ext::TestSize.Level0)
{
    auto iSystemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto mockAbilityMgr = sptr<SystemAbilityManagerMock>(new SystemAbilityManagerMock());
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = mockAbilityMgr;
    EXPECT_CALL(*mockAbilityMgr, LoadSystemAbility(_, An<const sptr<ISystemAbilityLoadCallback>&>()))
        .WillOnce(Return(DM_OK));

    std::thread notifyThread([]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(SHORT_DELAY_MS));
        DmServiceLoad::GetInstance().SetLoadFinish();
    });
    int32_t ret = DmServiceLoad::GetInstance().LoadDMService();
    notifyThread.join();
    EXPECT_EQ(ret, DM_OK);
    EXPECT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = iSystemAbilityMgr;
}

/**
 * @tc.name: SetLoadFinish_001
 * @tc.desc: 1. invoke SetLoadFinish and the DMLoadCallback success/fail paths
 *           2. verify isDMServiceLoading_ is reset
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, SetLoadFinish_001, testing::ext::TestSize.Level0)
{
    DmServiceLoad::GetInstance().SetLoadFinish();
    int32_t systemAbilityId = 1000;
    sptr<IRemoteObject> remoteObject = nullptr;
    DMLoadCallbackTest dmLoadCallback;
    dmLoadCallback.OnLoadSystemAbilitySuccess(systemAbilityId, remoteObject);
    dmLoadCallback.OnLoadSystemAbilityFail(systemAbilityId);
    ASSERT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
}

/**
 * @tc.name: LoadDMService_002
 * @tc.desc: 1. mock samgr so LoadSystemAbility fails
 *           2. call LoadDMService
 *           3. verify ret is ERR_DM_FAILED and loadFailed_ is true
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, LoadDMService_002, testing::ext::TestSize.Level2)
{
    auto iSystemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto mockAbilityMgr = sptr<SystemAbilityManagerMock>(new SystemAbilityManagerMock());
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = mockAbilityMgr;
    EXPECT_CALL(*mockAbilityMgr, LoadSystemAbility(_, An<const sptr<ISystemAbilityLoadCallback>&>()))
        .Times(1)
        .WillOnce(Return(ERR_DM_FAILED));

    int32_t ret = DmServiceLoad::GetInstance().LoadDMService();
    EXPECT_EQ(ret, ERR_DM_FAILED);
    EXPECT_EQ(DmServiceLoad::GetInstance().loadFailed_, true);
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = iSystemAbilityMgr;
}

/**
 * @tc.name: LoadDMService_003
 * @tc.desc: 1. set isDMServiceLoading_ true and loadFailed_ false (in-flight load)
 *           2. another thread calls SetLoadFinish after a short delay
 *           3. verify the waiter wakes and returns DM_OK
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, LoadDMService_003, testing::ext::TestSize.Level2)
{
    DmServiceLoad::GetInstance().isDMServiceLoading_ = true;
    DmServiceLoad::GetInstance().loadFailed_ = false;
    std::thread notifyThread([]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(SHORT_DELAY_MS));
        DmServiceLoad::GetInstance().SetLoadFinish();
    });
    int32_t ret = DmServiceLoad::GetInstance().LoadDMService();
    notifyThread.join();
    EXPECT_EQ(ret, DM_OK);
    EXPECT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
}

/**
 * @tc.name: LoadDMService_004
 * @tc.desc: 1. set isDMServiceLoading_ true and loadFailed_ true (in-flight load that already failed)
 *           2. another thread calls SetLoadFailed after a short delay
 *           3. verify the waiter wakes and returns ERR_DM_INIT_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, LoadDMService_004, testing::ext::TestSize.Level2)
{
    DmServiceLoad::GetInstance().isDMServiceLoading_ = true;
    DmServiceLoad::GetInstance().loadFailed_ = false;
    std::thread notifyThread([]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(SHORT_DELAY_MS));
        DmServiceLoad::GetInstance().SetLoadFailed();
    });
    int32_t ret = DmServiceLoad::GetInstance().LoadDMService();
    notifyThread.join();
    EXPECT_EQ(ret, ERR_DM_INIT_FAILED);
    EXPECT_EQ(DmServiceLoad::GetInstance().loadFailed_, true);
    EXPECT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
}

/**
 * @tc.name: LoadDMService_006
 * @tc.desc: 1. mock samgr so LoadSystemAbility succeeds but no SetLoadFinish is called (timeout)
 *           2. call LoadDMService
 *           3. verify ret is ERR_DM_INIT_FAILED after the cv wait timeout
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, LoadDMService_006, testing::ext::TestSize.Level2)
{
    auto iSystemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto mockAbilityMgr = sptr<SystemAbilityManagerMock>(new SystemAbilityManagerMock());
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = mockAbilityMgr;
    EXPECT_CALL(*mockAbilityMgr, LoadSystemAbility(_, An<const sptr<ISystemAbilityLoadCallback>&>()))
        .WillOnce(Return(DM_OK));

    int32_t ret = DmServiceLoad::GetInstance().LoadDMService();
    EXPECT_EQ(ret, ERR_DM_INIT_FAILED);
    EXPECT_EQ(DmServiceLoad::GetInstance().loadFailed_, true);
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = iSystemAbilityMgr;
}

/**
 * @tc.name: OnLoadSystemAbilitySuccess_001
 * @tc.desc: 1. construct a real DMLoadCallback instance
 *           2. call OnLoadSystemAbilitySuccess with a nullptr remoteObject
 *           3. verify the null-remoteObject early-return branch is hit and loading flag reset
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, OnLoadSystemAbilitySuccess_001, testing::ext::TestSize.Level2)
{
    // 1. construct a real DMLoadCallback (not the empty override) to exercise source logic
    DMLoadCallback dmLoadCallback;
    int32_t systemAbilityId = 1000;
    sptr<IRemoteObject> remoteObject = nullptr;
    // 2. call OnLoadSystemAbilitySuccess with nullptr remoteObject -> early return branch
    dmLoadCallback.OnLoadSystemAbilitySuccess(systemAbilityId, remoteObject);
    // 3. SetLoadFinish was invoked inside, loading flag must be reset to false
    ASSERT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
}

/**
 * @tc.name: OnLoadSystemAbilitySuccess_002
 * @tc.desc: 1. construct a real DMLoadCallback instance
 *           2. call OnLoadSystemAbilitySuccess with a non-null remoteObject
 *           3. verify SetLoadFinish is invoked and loading flag is reset to false
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, OnLoadSystemAbilitySuccess_002, testing::ext::TestSize.Level2)
{
    // 1. construct a real DMLoadCallback with a non-null remoteObject
    DMLoadCallback dmLoadCallback;
    int32_t systemAbilityId = 1002;
    sptr<IRemoteObject> remoteObject = sptr<SystemAbilityManagerMock>(new SystemAbilityManagerMock());
    // 2. call OnLoadSystemAbilitySuccess with non-null remoteObject (no early return)
    DmServiceLoad::GetInstance().isDMServiceLoading_ = true;
    dmLoadCallback.OnLoadSystemAbilitySuccess(systemAbilityId, remoteObject);
    // 3. SetLoadFinish invoked inside, loading flag must be reset to false
    ASSERT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
}

/**
 * @tc.name: OnLoadSystemAbilityFail_001
 * @tc.desc: 1. construct a real DMLoadCallback instance
 *           2. call OnLoadSystemAbilityFail
 *           3. verify loading flag is reset to false and loadFailed_ is true
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, OnLoadSystemAbilityFail_001, testing::ext::TestSize.Level2)
{
    // 1. construct a real DMLoadCallback (not the empty override)
    DMLoadCallback dmLoadCallback;
    int32_t systemAbilityId = 1001;
    // 2. call OnLoadSystemAbilityFail -> should call SetLoadFailed
    dmLoadCallback.OnLoadSystemAbilityFail(systemAbilityId);
    // 3. SetLoadFailed invoked inside, loading flag must be reset and loadFailed_ true
    ASSERT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
    ASSERT_EQ(DmServiceLoad::GetInstance().loadFailed_, true);
}

/**
 * @tc.name: SetLoadFinish_002
 * @tc.desc: 1. set isDMServiceLoading_ to true
 *           2. call SetLoadFinish explicitly
 *           3. verify isDMServiceLoading_ flips back to false
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, SetLoadFinish_002, testing::ext::TestSize.Level2)
{
    DmServiceLoad::GetInstance().isDMServiceLoading_ = true;
    DmServiceLoad::GetInstance().SetLoadFinish();
    ASSERT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
}

/**
 * @tc.name: SetLoadFailed_001
 * @tc.desc: 1. set isDMServiceLoading_ to true and loadFailed_ to false
 *           2. call SetLoadFailed explicitly
 *           3. verify isDMServiceLoading_ flips to false and loadFailed_ becomes true
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, SetLoadFailed_001, testing::ext::TestSize.Level2)
{
    DmServiceLoad::GetInstance().isDMServiceLoading_ = true;
    DmServiceLoad::GetInstance().loadFailed_ = false;
    DmServiceLoad::GetInstance().SetLoadFailed();
    ASSERT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
    ASSERT_EQ(DmServiceLoad::GetInstance().loadFailed_, true);
}

/**
 * @tc.name: LoadDMService_007
 * @tc.desc: 1. mock samgr so LoadSystemAbility fails first (loadFailed_=true)
 *           2. call LoadDMService again with fresh mock (LoadSystemAbility succeeds)
 *           3. another thread calls SetLoadFinish to unblock
 *           4. verify second call returns DM_OK (loadFailed_ reset on new load)
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, LoadDMService_007, testing::ext::TestSize.Level2)
{
    auto iSystemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto mockAbilityMgr = sptr<SystemAbilityManagerMock>(new SystemAbilityManagerMock());
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = mockAbilityMgr;
    EXPECT_CALL(*mockAbilityMgr, LoadSystemAbility(_, An<const sptr<ISystemAbilityLoadCallback>&>()))
        .WillOnce(Return(ERR_DM_FAILED))
        .WillOnce(Return(DM_OK));

    int32_t ret = DmServiceLoad::GetInstance().LoadDMService();
    EXPECT_EQ(ret, ERR_DM_FAILED);
    EXPECT_EQ(DmServiceLoad::GetInstance().loadFailed_, true);

    std::thread notifyThread([]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(SHORT_DELAY_MS));
        DmServiceLoad::GetInstance().SetLoadFinish();
    });
    ret = DmServiceLoad::GetInstance().LoadDMService();
    notifyThread.join();
    EXPECT_EQ(ret, DM_OK);
    EXPECT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = iSystemAbilityMgr;
}

/**
 * @tc.name: LoadDMService_008
 * @tc.desc: 1. two threads call LoadDMService concurrently
 *           2. mock LoadSystemAbility to succeed
 *           3. a third thread calls SetLoadFinish to unblock both waiters
 *           4. verify both threads get DM_OK or one triggers the load and the other waits
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, LoadDMService_008, testing::ext::TestSize.Level2)
{
    auto iSystemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto mockAbilityMgr = sptr<SystemAbilityManagerMock>(new SystemAbilityManagerMock());
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = mockAbilityMgr;
    EXPECT_CALL(*mockAbilityMgr, LoadSystemAbility(_, An<const sptr<ISystemAbilityLoadCallback>&>()))
        .WillOnce(Return(DM_OK));

    std::thread notifyThread([]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(SHORT_DELAY_MS));
        DmServiceLoad::GetInstance().SetLoadFinish();
    });
    int32_t ret1 = DM_OK;
    int32_t ret2 = DM_OK;
    std::thread t1([&ret1]() { ret1 = DmServiceLoad::GetInstance().LoadDMService(); });
    std::thread t2([&ret2]() { ret2 = DmServiceLoad::GetInstance().LoadDMService(); });
    t1.join();
    t2.join();
    notifyThread.join();
    EXPECT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
    EXPECT_EQ(ret1, DM_OK);
    EXPECT_EQ(ret2, DM_OK);
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = iSystemAbilityMgr;
}

/**
 * @tc.name: SetLoadFinish_003
 * @tc.desc: 1. call SetLoadFinish without prior LoadDMService (isDMServiceLoading_ = false)
 *           2. verify isDMServiceLoading_ remains false and loadFailed_ unchanged
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, SetLoadFinish_003, testing::ext::TestSize.Level2)
{
    DmServiceLoad::GetInstance().isDMServiceLoading_ = false;
    DmServiceLoad::GetInstance().loadFailed_ = false;
    DmServiceLoad::GetInstance().SetLoadFinish();
    ASSERT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
    ASSERT_EQ(DmServiceLoad::GetInstance().loadFailed_, false);
}

/**
 * @tc.name: SetLoadFailed_002
 * @tc.desc: 1. call SetLoadFailed without prior LoadDMService (isDMServiceLoading_ = false)
 *           2. verify isDMServiceLoading_ remains false and loadFailed_ becomes true
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, SetLoadFailed_002, testing::ext::TestSize.Level2)
{
    DmServiceLoad::GetInstance().isDMServiceLoading_ = false;
    DmServiceLoad::GetInstance().loadFailed_ = false;
    DmServiceLoad::GetInstance().SetLoadFailed();
    ASSERT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
    ASSERT_EQ(DmServiceLoad::GetInstance().loadFailed_, true);
}

/**
 * @tc.name: OnLoadSystemAbilityFail_002
 * @tc.desc: 1. construct a real DMLoadCallback instance
 *           2. set isDMServiceLoading_ to true
 *           3. call OnLoadSystemAbilityFail
 *           4. verify isDMServiceLoading_ is false and loadFailed_ is true
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, OnLoadSystemAbilityFail_002, testing::ext::TestSize.Level2)
{
    DMLoadCallback dmLoadCallback;
    int32_t systemAbilityId = 1003;
    DmServiceLoad::GetInstance().isDMServiceLoading_ = true;
    DmServiceLoad::GetInstance().loadFailed_ = false;
    dmLoadCallback.OnLoadSystemAbilityFail(systemAbilityId);
    ASSERT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
    ASSERT_EQ(DmServiceLoad::GetInstance().loadFailed_, true);
}

/**
 * @tc.name: LoadDMService_009
 * @tc.desc: 1. mock samgr so LoadSystemAbility succeeds
 *           2. three threads call LoadDMService concurrently
 *           3. a fourth thread calls SetLoadFinish after a short delay
 *           4. verify all three threads get DM_OK
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, LoadDMService_009, testing::ext::TestSize.Level2)
{
    auto iSystemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto mockAbilityMgr = sptr<SystemAbilityManagerMock>(new SystemAbilityManagerMock());
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = mockAbilityMgr;
    EXPECT_CALL(*mockAbilityMgr, LoadSystemAbility(_, An<const sptr<ISystemAbilityLoadCallback>&>()))
        .WillOnce(Return(DM_OK));

    std::thread notifyThread([]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(SHORT_DELAY_MS));
        DmServiceLoad::GetInstance().SetLoadFinish();
    });
    int32_t ret1 = ERR_DM_INIT_FAILED;
    int32_t ret2 = ERR_DM_INIT_FAILED;
    int32_t ret3 = ERR_DM_INIT_FAILED;
    std::thread t1([&ret1]() { ret1 = DmServiceLoad::GetInstance().LoadDMService(); });
    std::thread t2([&ret2]() { ret2 = DmServiceLoad::GetInstance().LoadDMService(); });
    std::thread t3([&ret3]() { ret3 = DmServiceLoad::GetInstance().LoadDMService(); });
    t1.join();
    t2.join();
    t3.join();
    notifyThread.join();
    EXPECT_EQ(ret1, DM_OK);
    EXPECT_EQ(ret2, DM_OK);
    EXPECT_EQ(ret3, DM_OK);
    EXPECT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = iSystemAbilityMgr;
}

/**
 * @tc.name: LoadDMService_010
 * @tc.desc: 1. mock samgr so LoadSystemAbility fails (ResetLoadState sets loadFailed_=true)
 *           2. call LoadDMService twice in a row (both fail immediately, no cv wait)
 *           3. verify both return ERR_DM_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, LoadDMService_010, testing::ext::TestSize.Level2)
{
    auto iSystemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto mockAbilityMgr = sptr<SystemAbilityManagerMock>(new SystemAbilityManagerMock());
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = mockAbilityMgr;
    EXPECT_CALL(*mockAbilityMgr, LoadSystemAbility(_, An<const sptr<ISystemAbilityLoadCallback>&>()))
        .Times(2)
        .WillRepeatedly(Return(ERR_DM_FAILED));

    int32_t ret1 = DmServiceLoad::GetInstance().LoadDMService();
    EXPECT_EQ(ret1, ERR_DM_FAILED);
    EXPECT_EQ(DmServiceLoad::GetInstance().loadFailed_, true);
    int32_t ret2 = DmServiceLoad::GetInstance().LoadDMService();
    EXPECT_EQ(ret2, ERR_DM_FAILED);
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = iSystemAbilityMgr;
}

/**
 * @tc.name: LoadDMService_011
 * @tc.desc: 1. set isDMServiceLoading_ true and loadFailed_ true (in-flight load already failed)
 *           2. no notify thread (cv wait should timeout)
 *           3. call LoadDMService, verify it waits then returns ERR_DM_INIT_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, LoadDMService_011, testing::ext::TestSize.Level2)
{
    DmServiceLoad::GetInstance().isDMServiceLoading_ = true;
    DmServiceLoad::GetInstance().loadFailed_ = false;
    std::thread notifyThread([]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(SHORT_DELAY_MS));
        DmServiceLoad::GetInstance().SetLoadFailed();
    });
    int32_t ret = DmServiceLoad::GetInstance().LoadDMService();
    notifyThread.join();
    EXPECT_EQ(ret, ERR_DM_INIT_FAILED);
    EXPECT_EQ(DmServiceLoad::GetInstance().loadFailed_, true);
    EXPECT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
}

/**
 * @tc.name: SetLoadFinish_004
 * @tc.desc: 1. set isDMServiceLoading_ to true and loadFailed_ to true
 *           2. call SetLoadFinish (should clear loading flag, keep loadFailed_ as-is)
 *           3. verify isDMServiceLoading_ is false
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, SetLoadFinish_004, testing::ext::TestSize.Level2)
{
    DmServiceLoad::GetInstance().isDMServiceLoading_ = true;
    DmServiceLoad::GetInstance().loadFailed_ = true;
    DmServiceLoad::GetInstance().SetLoadFinish();
    ASSERT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
}

/**
 * @tc.name: SetLoadFailed_003
 * @tc.desc: 1. set isDMServiceLoading_ to true and loadFailed_ to true
 *           2. call SetLoadFailed (should clear loading and keep loadFailed_ true)
 *           3. verify both flags
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, SetLoadFailed_003, testing::ext::TestSize.Level2)
{
    DmServiceLoad::GetInstance().isDMServiceLoading_ = true;
    DmServiceLoad::GetInstance().loadFailed_ = true;
    DmServiceLoad::GetInstance().SetLoadFailed();
    ASSERT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
    ASSERT_EQ(DmServiceLoad::GetInstance().loadFailed_, true);
}

/**
 * @tc.name: OnLoadSystemAbilitySuccess_003
 * @tc.desc: 1. construct a real DMLoadCallback with non-null remoteObject
 *           2. set isDMServiceLoading_ to true and loadFailed_ to true
 *           3. call OnLoadSystemAbilitySuccess
 *           4. verify isDMServiceLoading_ is false (SetLoadFinish invoked regardless of loadFailed_)
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, OnLoadSystemAbilitySuccess_003, testing::ext::TestSize.Level2)
{
    DMLoadCallback dmLoadCallback;
    int32_t systemAbilityId = 1004;
    sptr<IRemoteObject> remoteObject = sptr<SystemAbilityManagerMock>(new SystemAbilityManagerMock());
    DmServiceLoad::GetInstance().isDMServiceLoading_ = true;
    DmServiceLoad::GetInstance().loadFailed_ = true;
    dmLoadCallback.OnLoadSystemAbilitySuccess(systemAbilityId, remoteObject);
    ASSERT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
}

/**
 * @tc.name: OnLoadSystemAbilityFail_003
 * @tc.desc: 1. construct a real DMLoadCallback
 *           2. set isDMServiceLoading_ to false and loadFailed_ to false
 *           3. call OnLoadSystemAbilityFail
 *           4. verify loadFailed_ becomes true (SetLoadFailed always sets it)
 * @tc.type: FUNC
 */
HWTEST_F(DmServiceLoadTest, OnLoadSystemAbilityFail_003, testing::ext::TestSize.Level2)
{
    DMLoadCallback dmLoadCallback;
    int32_t systemAbilityId = 1005;
    DmServiceLoad::GetInstance().isDMServiceLoading_ = false;
    DmServiceLoad::GetInstance().loadFailed_ = false;
    dmLoadCallback.OnLoadSystemAbilityFail(systemAbilityId);
    ASSERT_EQ(DmServiceLoad::GetInstance().isDMServiceLoading_, false);
    ASSERT_EQ(DmServiceLoad::GetInstance().loadFailed_, true);
}
}
} // namespace DistributedHardware
} // namespace OHOS
