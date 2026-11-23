/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "app_manager_mock.h"
#include "ipc_skeleton_mock.h"
#include "multiple_user_connector.h"
#include "multiple_user_connector_3rd.h"
#include "os_account_from_uid_mock.h"
#include "os_account_manager_mock.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgReferee;

namespace OHOS {
namespace DistributedHardware {
namespace {
constexpr int32_t APP_UID = 10001;
constexpr int32_t SANDBOX_FORM_UID = 20010001;
constexpr int32_t LOCAL_USER_ID = 100;
constexpr int32_t INVALID_UID = -1;
constexpr int32_t INVALID_USER_ID = -1;
constexpr int32_t NOT_INIT_USER_ID = -100;
constexpr uint32_t CALLER_TOKEN_ID = 0xABCD1234;
constexpr int32_t MAIN_DISPLAY_ID = 0;
} // namespace

class CallerUserIdTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    std::shared_ptr<IPCSkeletonMock> skeleton_ = nullptr;
    std::shared_ptr<OsAccountFromUidMock> account_ = nullptr;
    std::shared_ptr<AppManagerMock> appManager_ = nullptr;
    std::shared_ptr<OsAccountManagerMock> accountManager_ = nullptr;
};

void CallerUserIdTest::SetUpTestCase()
{
}

void CallerUserIdTest::TearDownTestCase()
{
}

void CallerUserIdTest::SetUp()
{
    skeleton_ = std::static_pointer_cast<IPCSkeletonMock>(IPCSkeletonInterface::GetOrCreateIPCSkeleton());
    account_ = std::static_pointer_cast<OsAccountFromUidMock>(
        IOsAccountFromUidManager::GetOrCreateOsAccountFromUidManager());
    appManager_ = std::make_shared<AppManagerMock>();
    DmAppManager::dmAppManager = appManager_;
    accountManager_ = std::static_pointer_cast<OsAccountManagerMock>(
        IOsAccountManager::GetOrCreateOsAccountManager());
}

void CallerUserIdTest::TearDown()
{
    IPCSkeletonInterface::ReleaseIPCSkeleton();
    IOsAccountFromUidManager::ReleaseOsAccountFromUidManager();
    IOsAccountManager::ReleaseAccountManager();
    DmAppManager::dmAppManager = nullptr;
    skeleton_ = nullptr;
    account_ = nullptr;
    appManager_ = nullptr;
    accountManager_ = nullptr;
}

/**
 * @tc.name: GetCallerUserIdByAppUid_001
 * @tc.desc: GetCallerUserId uses the application uid returned by IPCSkeleton::GetCallingAppUid to query
 *           the owning user, instead of the process's own uid, and fills userId back on a successful query.
 * @tc.type: FUNC
 */
HWTEST_F(CallerUserIdTest, GetCallerUserIdByAppUid_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(skeleton_ != nullptr);
    ASSERT_TRUE(account_ != nullptr);

    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(APP_UID));
    EXPECT_CALL(*account_, GetOsAccountLocalIdFromUid(APP_UID, _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<1>(LOCAL_USER_ID), Return(0)));

    int32_t userId = NOT_INIT_USER_ID;
    MultipleUserConnector::GetCallerUserId(userId);
    EXPECT_EQ(userId, LOCAL_USER_ID);
}

/**
 * @tc.name: GetCallerUserIdByAppUid_002
 * @tc.desc: When the caller uid is in sandbox form (20000000 + application uid), it is passed through to
 *           the account subsystem unchanged, without truncation or re-conversion.
 * @tc.type: FUNC
 */
HWTEST_F(CallerUserIdTest, GetCallerUserIdByAppUid_002, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(skeleton_ != nullptr);
    ASSERT_TRUE(account_ != nullptr);

    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(SANDBOX_FORM_UID));
    EXPECT_CALL(*account_, GetOsAccountLocalIdFromUid(SANDBOX_FORM_UID, _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<1>(LOCAL_USER_ID), Return(0)));

    int32_t userId = NOT_INIT_USER_ID;
    MultipleUserConnector::GetCallerUserId(userId);
    EXPECT_EQ(userId, LOCAL_USER_ID);
}

/**
 * @tc.name: GetCallerUserIdByAppUid_003
 * @tc.desc: For a non-application process (getappuid falls back to process uid 0), 0 is passed through and
 *           userId is not rewritten when the account query fails.
 * @tc.type: FUNC
 */
HWTEST_F(CallerUserIdTest, GetCallerUserIdByAppUid_003, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(skeleton_ != nullptr);
    ASSERT_TRUE(account_ != nullptr);

    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*account_, GetOsAccountLocalIdFromUid(0, _)).Times(1).WillOnce(Return(-1));

    int32_t userId = NOT_INIT_USER_ID;
    MultipleUserConnector::GetCallerUserId(userId);
    EXPECT_EQ(userId, NOT_INIT_USER_ID);
}

/**
 * @tc.name: GetCallerUserIdByAppUid_004
 * @tc.desc: For a non-local call, GetCallingAppUid returns -1, the uid is passed through to the account
 *           subsystem, and userId is not rewritten when the query fails.
 * @tc.type: FUNC
 */
HWTEST_F(CallerUserIdTest, GetCallerUserIdByAppUid_004, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(skeleton_ != nullptr);
    ASSERT_TRUE(account_ != nullptr);

    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(INVALID_UID));
    EXPECT_CALL(*account_, GetOsAccountLocalIdFromUid(INVALID_UID, _)).Times(1).WillOnce(Return(-1));

    int32_t userId = INVALID_USER_ID;
    MultipleUserConnector::GetCallerUserId(userId);
    EXPECT_EQ(userId, INVALID_USER_ID);
}

/**
 * @tc.name: GetCallerUserId3rdByAppUid_001
 * @tc.desc: MultipleUserConnector3rd::GetCallerUserId on the 3rd side must also use the application uid
 *           returned by IPCSkeleton::GetCallingAppUid to query the account.
 * @tc.type: FUNC
 */
HWTEST_F(CallerUserIdTest, GetCallerUserId3rdByAppUid_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(skeleton_ != nullptr);
    ASSERT_TRUE(account_ != nullptr);

    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(APP_UID));
    EXPECT_CALL(*account_, GetOsAccountLocalIdFromUid(APP_UID, _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<1>(LOCAL_USER_ID), Return(0)));

    int32_t userId = NOT_INIT_USER_ID;
    MultipleUserConnector3rd::GetCallerUserId(userId);
    EXPECT_EQ(userId, LOCAL_USER_ID);
}

/**
 * @tc.name: GetCallerUserId3rdByAppUid_002
 * @tc.desc: On the 3rd side, userId is not rewritten when the account query fails.
 * @tc.type: FUNC
 */
HWTEST_F(CallerUserIdTest, GetCallerUserId3rdByAppUid_002, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(skeleton_ != nullptr);
    ASSERT_TRUE(account_ != nullptr);

    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(APP_UID));
    EXPECT_CALL(*account_, GetOsAccountLocalIdFromUid(APP_UID, _)).Times(1).WillOnce(Return(-1));

    int32_t userId = INVALID_USER_ID;
    MultipleUserConnector3rd::GetCallerUserId(userId);
    EXPECT_EQ(userId, INVALID_USER_ID);
}

/**
 * @tc.name: GetTokenIdByCallingTokenId_001
 * @tc.desc: GetTokenId must use the return value of IPCSkeleton::GetCallingTokenID to fill tokenId,
 *           instead of using GetCallingFullTokenID or returning a fixed value.
 * @tc.type: FUNC
 */
HWTEST_F(CallerUserIdTest, GetTokenIdByCallingTokenId_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(skeleton_ != nullptr);

    EXPECT_CALL(*skeleton_, GetCallingTokenID()).Times(1).WillOnce(Return(CALLER_TOKEN_ID));

    uint32_t tokenId = 0;
    MultipleUserConnector::GetTokenId(tokenId);
    EXPECT_EQ(tokenId, CALLER_TOKEN_ID);
}

/**
 * @tc.name: GetCallingTokenIdByCallingTokenId_001
 * @tc.desc: GetCallingTokenId must use the return value of IPCSkeleton::GetCallingTokenID to fill tokenId.
 * @tc.type: FUNC
 */
HWTEST_F(CallerUserIdTest, GetCallingTokenIdByCallingTokenId_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(skeleton_ != nullptr);

    EXPECT_CALL(*skeleton_, GetCallingTokenID()).Times(1).WillOnce(Return(CALLER_TOKEN_ID));

    uint32_t tokenId = 0;
    MultipleUserConnector::GetCallingTokenId(tokenId);
    EXPECT_EQ(tokenId, CALLER_TOKEN_ID);
}

/**
 * @tc.name: GetCallingTokenId3rdByCallingTokenId_001
 * @tc.desc: MultipleUserConnector3rd::GetCallingTokenId on the 3rd side must also use the return value of
 *           IPCSkeleton::GetCallingTokenID to fill tokenId.
 * @tc.type: FUNC
 */
HWTEST_F(CallerUserIdTest, GetCallingTokenId3rdByCallingTokenId_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(skeleton_ != nullptr);

    EXPECT_CALL(*skeleton_, GetCallingTokenID()).Times(1).WillOnce(Return(CALLER_TOKEN_ID));

    uint32_t tokenId = 0;
    MultipleUserConnector3rd::GetCallingTokenId(tokenId);
    EXPECT_EQ(tokenId, CALLER_TOKEN_ID);
}

/**
 * @tc.name: GetUserIdByDisplayId_001
 * @tc.desc: When a valid displayId is passed, it must query the foreground user via
 *           OsAccountManager::GetForegroundOsAccountLocalId and fill userId, instead of returning a fixed
 *           value or the calling process's own user.
 * @tc.type: FUNC
 */
HWTEST_F(CallerUserIdTest, GetUserIdByDisplayId_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(accountManager_ != nullptr);

    EXPECT_CALL(*accountManager_, GetForegroundOsAccountLocalId(static_cast<uint64_t>(MAIN_DISPLAY_ID), _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<1>(LOCAL_USER_ID), Return(0)));

    int32_t userId = NOT_INIT_USER_ID;
    int32_t ret = MultipleUserConnector::GetUserIdByDisplayId(MAIN_DISPLAY_ID);
    EXPECT_EQ(ret, LOCAL_USER_ID);
}

/**
 * @tc.name: GetCallerUserIdInCarForSystemApp_001
 * @tc.desc: A system application (IsSystemSA is true) goes through the displayId resolution path and queries
 *           the foreground user via GetForegroundOsAccountLocalId; this path does not use GetCallingAppUid
 *           nor the account uid query.
 * @tc.type: FUNC
 */
HWTEST_F(CallerUserIdTest, GetCallerUserIdInCarForSystemApp_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(appManager_ != nullptr);
    ASSERT_TRUE(accountManager_ != nullptr);
    ASSERT_TRUE(skeleton_ != nullptr);

    EXPECT_CALL(*appManager_, IsSystemSA()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*appManager_, IsSystemApp()).Times(0);
    EXPECT_CALL(*accountManager_, GetForegroundOsAccountLocalId(static_cast<uint64_t>(MAIN_DISPLAY_ID), _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<1>(LOCAL_USER_ID), Return(0)));
    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(0);

    int32_t ret = MultipleUserConnector::GetCallerUserIdInCar("");
    EXPECT_EQ(ret, LOCAL_USER_ID);
}

/**
 * @tc.name: GetCallerUserIdInCarForNormalApp_001
 * @tc.desc: A normal application (both IsSystemSA and IsSystemApp are false) goes through the GetCallerUserId
 *           path, using the application uid returned by IPCSkeleton::GetCallingAppUid to query the account,
 *           without the foreground user query.
 * @tc.type: FUNC
 */
HWTEST_F(CallerUserIdTest, GetCallerUserIdInCarForNormalApp_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(appManager_ != nullptr);
    ASSERT_TRUE(skeleton_ != nullptr);
    ASSERT_TRUE(account_ != nullptr);
    ASSERT_TRUE(accountManager_ != nullptr);

    EXPECT_CALL(*appManager_, IsSystemSA()).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*appManager_, IsSystemApp()).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*skeleton_, GetCallingAppUid()).Times(1).WillOnce(Return(APP_UID));
    EXPECT_CALL(*account_, GetOsAccountLocalIdFromUid(APP_UID, _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<1>(LOCAL_USER_ID), Return(0)));
    EXPECT_CALL(*accountManager_, GetForegroundOsAccountLocalId(_, _)).Times(0);

    int32_t ret = MultipleUserConnector::GetCallerUserIdInCar("");
    EXPECT_EQ(ret, LOCAL_USER_ID);
}
} // namespace DistributedHardware
} // namespace OHOS
