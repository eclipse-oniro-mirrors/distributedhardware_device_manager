/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "UTTest_dm_transport_msg.h"

namespace OHOS {
namespace DistributedHardware {
void DMTransportMsgTest::SetUp()
{
}
void DMTransportMsgTest::TearDown()
{
}
void DMTransportMsgTest::SetUpTestCase()
{
}
void DMTransportMsgTest::TearDownTestCase()
{
}

/**
 * @tc.name: ToJsonAndFromJson
 * @tc.type: FUNC
 */
HWTEST_F(DMTransportMsgTest, ToJsonAndFromJson, testing::ext::TestSize.Level0)
{
    UserIdsMsg userIdsMsg;
    userIdsMsg.foregroundUserIds = {1, 2, 3};

    cJSON *jsonObject = cJSON_CreateObject();
    ToJson(jsonObject, userIdsMsg);
    
    UserIdsMsg newUserIdsMsg;
    FromJson(jsonObject, newUserIdsMsg);

    EXPECT_EQ(newUserIdsMsg.foregroundUserIds.size(), 3);
    EXPECT_EQ(newUserIdsMsg.foregroundUserIds[0], 1);
    EXPECT_EQ(newUserIdsMsg.foregroundUserIds[1], 2);
    EXPECT_EQ(newUserIdsMsg.foregroundUserIds[2], 3);

    cJSON_Delete(jsonObject);

    cJSON *emptyJsonObject = cJSON_CreateObject();
    UserIdsMsg emptyUserIdsMsg;
    FromJson(emptyJsonObject, emptyUserIdsMsg);
    
    EXPECT_EQ(emptyUserIdsMsg.foregroundUserIds.size(), 0);
    cJSON_Delete(emptyJsonObject);
}

/**
 * @tc.name: ToJsonAndFromJson01
 * @tc.type: FUNC
 */
HWTEST_F(DMTransportMsgTest, ToJsonAndFromJson01, testing::ext::TestSize.Level0)
{
    CommMsg commMsg;
    commMsg.code = 200;
    commMsg.msg = "Success";

    cJSON *jsonObject = cJSON_CreateObject();
    ToJson(jsonObject, commMsg);

    CommMsg newCommMsg;
    FromJson(jsonObject, newCommMsg);

    EXPECT_EQ(newCommMsg.code, 200);
    EXPECT_EQ(newCommMsg.msg, "Success");

    cJSON_Delete(jsonObject);

    cJSON *emptyCommJsonObject = cJSON_CreateObject();
    CommMsg emptyCommMsg;
    FromJson(emptyCommJsonObject, emptyCommMsg);

    EXPECT_EQ(emptyCommMsg.code, -1);
    EXPECT_EQ(emptyCommMsg.msg, "");
    cJSON_Delete(emptyCommJsonObject);
}

/**
 * @tc.name: PerformanceTest
 * @tc.type: FUNC
 */
HWTEST_F(DMTransportMsgTest, PerformanceTest, testing::ext::TestSize.Level0)
{
    UserIdsMsg userIdsMsg;
    for (int i = 0; i < 10000; ++i) {
        userIdsMsg.foregroundUserIds.push_back(i);
    }

    cJSON *jsonObject = cJSON_CreateObject();
    auto start = std::chrono::high_resolution_clock::now();
    ToJson(jsonObject, userIdsMsg);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    EXPECT_LT(elapsed.count(), 1.0);
    cJSON_Delete(jsonObject);
}

/**
 * @tc.name: GetCommMsgString_EmptyInput
 * @tc.type: FUNC
 */
HWTEST_F(DMTransportMsgTest, GetCommMsgString_EmptyInput, testing::ext::TestSize.Level0)
{
    CommMsg commMsg;
    std::string result = GetCommMsgString(commMsg);
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: ToJson_ValidInput
 * @tc.type: FUNC
 */
HWTEST_F(DMTransportMsgTest, ToJson_ValidInput, testing::ext::TestSize.Level0)
{
    cJSON *jsonObject = cJSON_CreateObject();
    NotifyUserIds notifyUserIds;
    notifyUserIds.remoteUdid = "test_udid";
    notifyUserIds.userIds = {1, 2, 3};

    ToJson(jsonObject, notifyUserIds);
    cJSON *udidItem = cJSON_GetObjectItem(jsonObject, DSOFTBUS_NOTIFY_USERIDS_UDIDKEY);
    EXPECT_STREQ(udidItem->valuestring, "test_udid");
    cJSON *userIdsArr = cJSON_GetObjectItem(jsonObject, DSOFTBUS_NOTIFY_USERIDS_USERIDKEY);
    EXPECT_EQ(cJSON_GetArraySize(userIdsArr), 3);
}

/**
 * @tc.name: FromJson_InvalidJson
 * @tc.type: FUNC
 */
HWTEST_F(DMTransportMsgTest, FromJson_InvalidJson, testing::ext::TestSize.Level0)
{
    const char *jsonString = "{\"udid\":123,\"userIds\":\"invalid\"}";
    cJSON *jsonObject = cJSON_Parse(jsonString);
    NotifyUserIds notifyUserIds;

    FromJson(jsonObject, notifyUserIds);
    EXPECT_TRUE(notifyUserIds.remoteUdid.empty());
    EXPECT_TRUE(notifyUserIds.userIds.empty());

    cJSON_Delete(jsonObject);
}

/**
 * @tc.name: NotifyUserIds_ToString_ValidInput
 * @tc.type: FUNC
 */
HWTEST_F(DMTransportMsgTest, NotifyUserIds_ToString_ValidInput, testing::ext::TestSize.Level0)
{
    NotifyUserIds notifyUserIds;
    notifyUserIds.remoteUdid = "test_udid";
    notifyUserIds.userIds = {1, 2, 3};

    std::string result = notifyUserIds.ToString();
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: NotifyUserIds_ToString_EmptyInput
 * @tc.type: FUNC
 */
HWTEST_F(DMTransportMsgTest, NotifyUserIds_ToString_EmptyInput, testing::ext::TestSize.Level0)
{
    NotifyUserIds notifyUserIds;
    std::string result = notifyUserIds.ToString();
    EXPECT_FALSE(result.empty());
}
} // DistributedHardware
} // OHOS