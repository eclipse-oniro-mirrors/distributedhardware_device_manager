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

#include "UTTest_device_manager_notify.h"
#include "device_manager_notify.h"
#include "dm_device_info.h"
#include "ipc_remote_broker.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "ipc_client_manager.h"
#include "ipc_set_useroperation_req.h"
#include "ipc_rsp.h"
#include "ipc_def.h"

#include <unistd.h>

namespace OHOS {
namespace DistributedHardware {
namespace {
/*
 * Feature: DeviceManagerNotifyTest OnPublishResult
 * Function: DeviceManagerNotifyTest
 * SubFunction: OnPublishResult
 * FunctionPoints: DeviceManagerNotifyTest OnPublishResult
 * EnvConditions: OnPublishResult success.
 * CaseDescription: 1. set pkgName not null
 *                     set callback not null
 *                     set publishId not null
 *                  2. set checkMap null
 *                  3. call DeviceManagerNotifyTest RegisterPublishCallback with parameter
 *                  4. Get checkMap from DeviceManagerNotify
 *                  5. check checkMap not null
 *                  6. call DeviceManagerNotify OnPublishResult
 *                  7. check if callback OnPublishResult called.
 */
HWTEST_F(DeviceManagerNotifyTest, OnPublishSuccess1, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // set callback not null
    int count = 0;
    std::shared_ptr<PublishCallback> callback = std::make_shared<PublishCallbackTest>(count);
    // set publishId not null
    int32_t publishId = 0;
    // 2. set checkMap null
    std::shared_ptr<PublishCallback> checkMap = nullptr;
    // 3. call DeviceManagerNotifyTest RegisterPublishCallback with parameter
    DeviceManagerNotify::GetInstance().RegisterPublishCallback(pkgName, publishId, callback);
    // 4. Get checkMap from DeviceManagerNotify
    checkMap = DeviceManagerNotify::GetInstance().devicePublishCallbacks_[pkgName][publishId];
    // 5. check checkMap not null
    ASSERT_NE(checkMap, nullptr);
    // 6. call DeviceManagerNotify OnPublishResult
    DeviceManagerNotify::GetInstance().OnPublishResult(pkgName, publishId, 0);
    // 7. check if callback OnPublishResult called
    ASSERT_EQ(count, 1);
}

/*
 * Feature: DeviceManagerNotifyTest OnPublishResult
 * Function: DeviceManagerNotifyTest
 * SubFunction: OnPublishResult
 * FunctionPoints: DeviceManagerNotifyTest OnPublishResult
 * EnvConditions: N/A.
 * CaseDescription: 1. set pkgName not null
 *                     set callback not null
 *                     set publishId not null
 *                  2. set checkMap null
 *                  3. call DeviceManagerNotifyTest RegisterPublishCallback with parameter
 *                  4. Get checkMap from DeviceManagerNotify
 *                  5. check checkMap not null
 *                  6. call DeviceManagerNotify OnPublishResult With testPkgName
 *                  7. check if callback OnPublishResult called.
 */
HWTEST_F(DeviceManagerNotifyTest, OnPublishSuccess2, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // set callback not null
    int count = 0;
    std::shared_ptr<PublishCallback> callback = std::make_shared<PublishCallbackTest>(count);
    // set publishId not null
    int32_t publishId = 0;
    // 2. set checkMap null
    std::shared_ptr<PublishCallback> checkMap = nullptr;
    // 3. call DeviceManagerNotifyTest RegisterPublishCallback with parameter
    DeviceManagerNotify::GetInstance().RegisterPublishCallback(pkgName, publishId, callback);
    // 4. Get checkMap from DeviceManagerNotify
    checkMap = DeviceManagerNotify::GetInstance().devicePublishCallbacks_[pkgName][publishId];
    // 5. check checkMap not null
    ASSERT_NE(checkMap, nullptr);
    std::string testPkgName = "com.ohos.test1";
    // 6. call DeviceManagerNotify OnPublishResult
    DeviceManagerNotify::GetInstance().OnPublishResult(testPkgName, publishId, 0);
    // 7. check if callback OnPublishResult called
    ASSERT_EQ(count, 0);
}

/*
 * Feature: DeviceManagerNotifyTest OnPublishResult
 * Function: DeviceManagerNotifyTest
 * SubFunction: OnPublishResult
 * FunctionPoints: DeviceManagerNotifyTest OnPublishResult
 * EnvConditions: N/A.
 * CaseDescription: 1. set pkgName not null
 *                     set callback not null
 *                     set publishId not null
 *                  2. set checkMap null
 *                  3. call DeviceManagerNotifyTest RegisterPublishCallback with parameter
 *                  4. Get checkMap from DeviceManagerNotify
 *                  5. check checkMap not null
 *                  6. call DeviceManagerNotify OnPublishResult With testpublishId
 *                  7. check if callback OnPublishResult called.
 */
HWTEST_F(DeviceManagerNotifyTest, OnPublishSuccess3, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // set callback not null
    int count = 0;
    std::shared_ptr<PublishCallback> callback = std::make_shared<PublishCallbackTest>(count);
    // set publishId not null
    int32_t publishId = 0;
    // 2. set checkMap null
    std::shared_ptr<PublishCallback> checkMap = nullptr;
    // 3. call DeviceManagerNotifyTest RegisterPublishCallback with parameter
    DeviceManagerNotify::GetInstance().RegisterPublishCallback(pkgName, publishId, callback);
    // 4. Get checkMap from DeviceManagerNotify
    checkMap = DeviceManagerNotify::GetInstance().devicePublishCallbacks_[pkgName][publishId];
    // 5. check checkMap not null
    ASSERT_NE(checkMap, nullptr);
    int32_t testpublishId = 1;
    // 6. call DeviceManagerNotify OnPublishResult
    DeviceManagerNotify::GetInstance().OnPublishResult(pkgName, testpublishId, 0);
    // 7. check if callback OnPublishResult called
    ASSERT_EQ(count, 0);
}

/*
 * Feature: DeviceManagerNotifyTest OnPublishResult
 * Function: DeviceManagerNotifyTest
 * SubFunction: OnPublishResult Success
 * FunctionPoints: DeviceManagerNotifyTest OnPublishResult
 * EnvConditions: N/A.
 * CaseDescription: 1. set pkgName not null
 *                     set callback not null
 *                     set publishId not null
 *                  2. set checkMap null
 *                  3. call DeviceManagerNotifyTest RegisterPublishCallback with parameter
 *                  4. Get checkMap from DeviceManagerNotify
 *                  5. check checkMap not null
 *                  6. call DeviceManagerNotify OnPublishResult With testPkgName
 *                  7. check if callback OnPublishResult called.
 */
HWTEST_F(DeviceManagerNotifyTest, OnPublishSuccess4, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // set callback not null
    int count = 0;
    std::shared_ptr<PublishCallback> callback = std::make_shared<PublishCallbackTest>(count);
    // set publishId not null
    int32_t publishId = 0;
    // 2. set checkMap null
    std::shared_ptr<PublishCallback> checkMap = nullptr;
    // 3. call DeviceManagerNotifyTest RegisterPublishCallback with parameter
    DeviceManagerNotify::GetInstance().RegisterPublishCallback(pkgName, publishId, callback);
    // 4. Get checkMap from DeviceManagerNotify
    checkMap = DeviceManagerNotify::GetInstance().devicePublishCallbacks_[pkgName][publishId];
    // 5. check checkMap not null
    ASSERT_NE(checkMap, nullptr);
    std::string testPkgName = "";
    // 6. call DeviceManagerNotify OnPublishResult
    DeviceManagerNotify::GetInstance().OnPublishResult(testPkgName, publishId, 0);
    // 7. check if callback OnPublishResult called
    ASSERT_EQ(count, 0);
}

/*
 * Feature: DeviceManagerNotifyTest OnPublishResult
 * Function: DeviceManagerNotifyTest
 * SubFunction: OnPublishResult Success
 * FunctionPoints: DeviceManagerNotifyTest OnPublishResult
 * EnvConditions: N/A.
 * CaseDescription: 1. set pkgName not null
 *                     set callback not null
 *                     set subscribeId not null
 *                  2. set checkMap null
 *                  3. call DeviceManagerNotifyTest RegisterPublishCallback with parameter
 *                  4. Get checkMap from DeviceManagerNotify
 *                  5. check checkMap not null
 *                  6. call DeviceManagerNotify OnPublishResult With testPkgName
 *                  7. check if callback OnPublishResult called.
 */
HWTEST_F(DeviceManagerNotifyTest, OnPublishSuccess5, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // set callback not null
    int count = 0;
    std::shared_ptr<PublishCallback> callback = std::make_shared<PublishCallbackTest>(count);
    // set publishId not null
    int32_t publishId = 0;
    // 2. set checkMap null
    std::shared_ptr<PublishCallback> checkMap = nullptr;
    // 3. call DeviceManagerNotifyTest RegisterDiscoverCallback with parameter
    DeviceManagerNotify::GetInstance().RegisterPublishCallback(pkgName, publishId, callback);
    // 4. Get checkMap from DeviceManagerNotify
    checkMap = DeviceManagerNotify::GetInstance().devicePublishCallbacks_[pkgName][publishId];
    // 5. check checkMap not null
    ASSERT_NE(checkMap, nullptr);
    std::string testPkgName = "";
    DeviceManagerNotify::GetInstance().UnRegisterPublishCallback(testPkgName, publishId);
    // 6. call DeviceManagerNotify OnPublishResult
    DeviceManagerNotify::GetInstance().OnPublishResult(testPkgName, publishId, 0);
    // 7. check if callback OnPublishSuccess called
    ASSERT_EQ(count, 0);
}

/*
 * Feature: DeviceManagerNotifyTest OnAuthResult
 * Function: OnAuthResult
 * SubFunction: RegisterAuthenticateCallback
 * FunctionPoints: DeviceManagerNotifyTest OnAuthResult
 * EnvConditions: OnAuthResult success.
 * CaseDescription: 1. set pkgName not null
 *                     set Callback not null
 *                     set deviceId not null
 *                  2. set checkMap null
 *                  3. call DeviceManagerNotifyTest RegisterAuthenticateCallback with parameter
 *                  4. Get checkMap from DeviceManagerNotify
 *                  5. check checkMap not null
 *                  6. call DeviceManagerNotify OnAuthResult
 *                  7. check if callback OnDiscoverySuccess called
 */
HWTEST_F(DeviceManagerNotifyTest, OnAuthResult1, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // set callback not null
    int count = 0;
    std::shared_ptr<AuthenticateCallback> callback = std::make_shared<AuthenticateCallbackTest>(count);
    // set subscribeId not null
    std::string deviceId = "1";
    // 2. set checkMap null
    std::shared_ptr<AuthenticateCallback> checkMap = nullptr;
    // 3. call DeviceManagerNotifyTest RegisterAuthenticateCallback with parameter
    DeviceManagerNotify::GetInstance().RegisterAuthenticateCallback(pkgName, deviceId, callback);
    // 4. Get checkMap from DeviceManagerNotify
    checkMap = DeviceManagerNotify::GetInstance().authenticateCallback_[pkgName][deviceId];
    // 5. check checkMap not null
    ASSERT_NE(checkMap, nullptr);
    // 6. call DeviceManagerNotify OnAuthResult
    std::string token = "111";
    uint32_t status = 0;
    uint32_t reason = 0;
    DeviceManagerNotify::GetInstance().OnAuthResult(pkgName, deviceId, token, status, reason);
    // 7. check if callback OnDiscoverySuccess called
    ASSERT_EQ(count, 1);
}

/*
 * Feature: DeviceManagerNotifyTest OnAuthResult
 * Function: OnAuthResult
 * SubFunction: RegisterAuthenticateCallback
 * FunctionPoints: DeviceManagerNotifyTest OnAuthResult
 * EnvConditions: OnAuthResult success.
 * CaseDescription: 1. set pkgName not null
 *                     set Callback not null
 *                     set deviceId not null
 *                  2. set checkMap null
 *                  3. call DeviceManagerNotifyTest RegisterAuthenticateCallback with parameter
 *                  4. Get checkMap from DeviceManagerNotify
 *                  5. check checkMap not null
 *                  6. call DeviceManagerNotify OnAuthResult with testPkgName
 *                  7. check if callback OnDiscoverySuccess called
 */
HWTEST_F(DeviceManagerNotifyTest, OnAuthResult2, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // set callback not null
    int count = 0;
    std::shared_ptr<AuthenticateCallback> callback = std::make_shared<AuthenticateCallbackTest>(count);
    // set subscribeId not null
    std::string deviceId = "1";
    // 2. set checkMap null
    std::shared_ptr<AuthenticateCallback> checkMap = nullptr;
    // 3. call DeviceManagerNotifyTest RegisterAuthenticateCallback with parameter
    DeviceManagerNotify::GetInstance().RegisterAuthenticateCallback(pkgName, deviceId, callback);
    // 4. Get checkMap from DeviceManagerNotify
    checkMap = DeviceManagerNotify::GetInstance().authenticateCallback_[pkgName][deviceId];
    // 5. check checkMap not null
    ASSERT_NE(checkMap, nullptr);
    // 6. call DeviceManagerNotify OnAuthResult
    std::string testPkgName = "com.ohos.test1";
    std::string token = "111";
    uint32_t status = 0;
    uint32_t reason = 0;
    DeviceManagerNotify::GetInstance().OnAuthResult(testPkgName, deviceId, token, status, reason);
    // 7. check if callback OnDiscoverySuccess called
    ASSERT_EQ(count, 0);
}

/*
 * Feature: DeviceManagerNotifyTest OnAuthResult
 * Function: OnAuthResult
 * SubFunction: RegisterAuthenticateCallback
 * FunctionPoints: DeviceManagerNotifyTest OnAuthResult
 * EnvConditions: OnAuthResult success.
 * CaseDescription: 1. set pkgName not null
 *                     set Callback not null
 *                     set deviceId not null
 *                  2. set checkMap null
 *                  3. call DeviceManagerNotifyTest RegisterAuthenticateCallback with parameter
 *                  4. Get checkMap from DeviceManagerNotify
 *                  5. check checkMap not null
 *                  6. call DeviceManagerNotify OnAuthResult with testDeviceId
 *                  7. check if callback OnDiscoverySuccess called
 */
HWTEST_F(DeviceManagerNotifyTest, OnAuthResult3, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // set callback not null
    int count = 0;
    std::shared_ptr<AuthenticateCallback> callback = std::make_shared<AuthenticateCallbackTest>(count);
    // set subscribeId not null
    std::string deviceId = "1";
    // 2. set checkMap null
    std::shared_ptr<AuthenticateCallback> checkMap = nullptr;
    // 3. call DeviceManagerNotifyTest RegisterAuthenticateCallback with parameter
    DeviceManagerNotify::GetInstance().RegisterAuthenticateCallback(pkgName, deviceId, callback);
    // 4. Get checkMap from DeviceManagerNotify
    checkMap = DeviceManagerNotify::GetInstance().authenticateCallback_[pkgName][deviceId];
    // 5. check checkMap not null
    ASSERT_NE(checkMap, nullptr);
    // 6. call DeviceManagerNotify OnAuthResult
    std::string testDeviceId = "2";
    std::string token = "111";
    uint32_t status = 0;
    uint32_t reason = 0;
    DeviceManagerNotify::GetInstance().OnAuthResult(pkgName, testDeviceId, token, status, reason);
    // 7. check if callback OnDiscoverySuccess called
    ASSERT_EQ(count, 0);
}

/*
 * Feature: DeviceManagerNotifyTest OnAuthResult
 * Function: OnAuthResult
 * SubFunction: RegisterAuthenticateCallback
 * FunctionPoints: DeviceManagerNotifyTest OnAuthResult
 * EnvConditions: OnAuthResult success.
 * CaseDescription: 1. set pkgName not null
 *                     set Callback not null
 *                     set deviceId not null
 *                  2. set checkMap null
 *                  3. call DeviceManagerNotifyTest RegisterAuthenticateCallback with parameter
 *                  4. Get checkMap from DeviceManagerNotify
 *                  5. check checkMap not null
 *                  6. call DeviceManagerNotify OnAuthResult
 *                  7. check if callback OnDiscoverySuccess called
 */
HWTEST_F(DeviceManagerNotifyTest, OnAuthResult4, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // set callback not null
    int count = 0;
    std::shared_ptr<AuthenticateCallback> callback = std::make_shared<AuthenticateCallbackTest>(count);
    // set subscribeId not null
    std::string deviceId = "1";
    // 2. set checkMap null
    std::shared_ptr<AuthenticateCallback> checkMap = nullptr;
    // 3. call DeviceManagerNotifyTest RegisterAuthenticateCallback with parameter
    DeviceManagerNotify::GetInstance().RegisterAuthenticateCallback(pkgName, deviceId, callback);
    // 4. Get checkMap from DeviceManagerNotify
    checkMap = DeviceManagerNotify::GetInstance().authenticateCallback_[pkgName][deviceId];
    // 5. check checkMap not null
    ASSERT_NE(checkMap, nullptr);
    // 6. call DeviceManagerNotify OnAuthResult
    std::string token = "111";
    uint32_t status = 0;
    uint32_t reason = 0;
    DeviceManagerNotify::GetInstance().OnAuthResult(pkgName, deviceId, token, status, reason);
    // 7. check if callback OnDiscoverySuccess called
    ASSERT_EQ(count, 1);
    checkMap = DeviceManagerNotify::GetInstance().authenticateCallback_[pkgName][deviceId];
    ASSERT_EQ(checkMap, nullptr);
}

/*
 * Feature: DeviceManagerNotifyTest OnAuthResult
 * Function: OnAuthResult
 * SubFunction: RegisterAuthenticateCallback
 * FunctionPoints: DeviceManagerNotifyTest OnAuthResult
 * EnvConditions: OnAuthResult success.
 * CaseDescription: 1. set pkgName not null
 *                     set Callback not null
 *                     set deviceId not null
 *                  2. set checkMap null
 *                  3. call DeviceManagerNotifyTest RegisterAuthenticateCallback with parameter
 *                  4. Get checkMap from DeviceManagerNotify
 *                  5. check checkMap not null
 *                  6. call DeviceManagerNotify OnAuthResult
 *                  7. check if callback OnDiscoverySuccess called
 */
HWTEST_F(DeviceManagerNotifyTest, OnAuthResult5, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // set callback not null
    int count = 0;
    std::shared_ptr<AuthenticateCallback> callback = std::make_shared<AuthenticateCallbackTest>(count);
    // set subscribeId not null
    std::string deviceId = "1";
    // 2. set checkMap null
    std::shared_ptr<AuthenticateCallback> checkMap = nullptr;
    // 3. call DeviceManagerNotifyTest RegisterAuthenticateCallback with parameter
    DeviceManagerNotify::GetInstance().RegisterAuthenticateCallback(pkgName, deviceId, callback);
    // 4. Get checkMap from DeviceManagerNotify
    checkMap = DeviceManagerNotify::GetInstance().authenticateCallback_[pkgName][deviceId];
    // 5. check checkMap not null
    ASSERT_NE(checkMap, nullptr);
    // 6. call DeviceManagerNotify OnAuthResult
    std::string testPkaName = "com.ohos.test1";
    std::string token = "111";
    uint32_t status = 0;
    uint32_t reason = 0;
    DeviceManagerNotify::GetInstance().OnAuthResult(testPkaName, deviceId, token, status, reason);
    // 7. check if callback OnDiscoverySuccess called
    ASSERT_EQ(count, 0);
    checkMap = DeviceManagerNotify::GetInstance().authenticateCallback_[pkgName][deviceId];
    ASSERT_NE(checkMap, nullptr);
}

/*
 * Feature: DeviceManagerNotifyTest OnAuthResult
 * Function: OnAuthResult
 * SubFunction: RegisterAuthenticateCallback
 * FunctionPoints: DeviceManagerNotifyTest OnAuthResult
 * EnvConditions: OnAuthResult success.
 * CaseDescription: 1. set pkgName not null
 *                     set Callback not null
 *                     set deviceId not null
 *                  2. set checkMap null
 *                  3. call DeviceManagerNotifyTest RegisterAuthenticateCallback with parameter
 *                  4. Get checkMap from DeviceManagerNotify
 *                  5. check checkMap not null
 *                  6. call DeviceManagerNotify OnAuthResult
 *                  7. check if callback OnDiscoverySuccess called
 */
HWTEST_F(DeviceManagerNotifyTest, OnAuthResult6, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // set callback not null
    int count = 0;
    std::shared_ptr<AuthenticateCallback> callback = std::make_shared<AuthenticateCallbackTest>(count);
    // set subscribeId not null
    std::string deviceId = "1";
    // 2. set checkMap null
    std::shared_ptr<AuthenticateCallback> checkMap = nullptr;
    // 3. call DeviceManagerNotifyTest RegisterAuthenticateCallback with parameter
    DeviceManagerNotify::GetInstance().RegisterAuthenticateCallback(pkgName, deviceId, callback);
    // 4. Get checkMap from DeviceManagerNotify
    checkMap = DeviceManagerNotify::GetInstance().authenticateCallback_[pkgName][deviceId];
    // 5. check checkMap not null
    ASSERT_NE(checkMap, nullptr);
    // 6. call DeviceManagerNotify OnAuthResult
    std::string testDeviceId = "2";
    std::string token = "111";
    uint32_t status = 0;
    uint32_t reason = 0;
    DeviceManagerNotify::GetInstance().OnAuthResult(pkgName, testDeviceId, token, status, reason);
    // 7. check if callback OnDiscoverySuccess called
    ASSERT_EQ(count, 0);
    checkMap = DeviceManagerNotify::GetInstance().authenticateCallback_[pkgName][deviceId];
    ASSERT_NE(checkMap, nullptr);
}

/*
 * Feature: DeviceManagerNotifyTest OnAuthResult
 * Function: OnAuthResult
 * SubFunction: RegisterAuthenticateCallback
 * FunctionPoints: DeviceManagerNotifyTest OnAuthResult
 * EnvConditions: OnAuthResult success.
 * CaseDescription: 1. set pkgName not null
 *                     set Callback not null
 *                     set deviceId not null
 *                  2. set checkMap null
 *                  3. call DeviceManagerNotifyTest RegisterAuthenticateCallback with parameter
 *                  4. Get checkMap from DeviceManagerNotify
 *                  5. check checkMap not null
 *                  6. call DeviceManagerNotify OnAuthResult
 *                  7. check if callback OnDiscoverySuccess called
 */
HWTEST_F(DeviceManagerNotifyTest, OnAuthResult7, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // set callback not null
    int count = 0;
    std::shared_ptr<AuthenticateCallback> callback = std::make_shared<AuthenticateCallbackTest>(count);
    // set subscribeId not null
    std::string deviceId = "1";
    // 2. set checkMap null
    std::shared_ptr<AuthenticateCallback> checkMap = nullptr;
    // 3. call DeviceManagerNotifyTest RegisterAuthenticateCallback with parameter
    DeviceManagerNotify::GetInstance().RegisterAuthenticateCallback(pkgName, deviceId, callback);
    // 4. Get checkMap from DeviceManagerNotify
    checkMap = DeviceManagerNotify::GetInstance().authenticateCallback_[pkgName][deviceId];
    // 5. check checkMap not null
    ASSERT_NE(checkMap, nullptr);
    // 6. call DeviceManagerNotify OnAuthResult
    std::string token = "111";
    uint32_t status = 0;
    uint32_t reason = 0;
    DeviceManagerNotify::GetInstance().OnAuthResult(pkgName, deviceId, token, status, reason);
    // 7. check if callback OnDiscoverySuccess called
    ASSERT_EQ(count, 1);
    checkMap = DeviceManagerNotify::GetInstance().authenticateCallback_[pkgName][deviceId];
    ASSERT_EQ(checkMap, nullptr);
}

/*
 * Feature: DeviceManagerNotifyTest OnUiCall
 * Function: DeviceManagerNotifyTest
 * SubFunction: OnUiCall
 * FunctionPoints: DeviceManagerNotifyTest OnUiCall
 * EnvConditions: OnUiCall success.
 * CaseDescription: 1. set pkgName not null
 *                     set dmUiCallback_ not null
 *                  2. set checkMap null
 *                  3. call DeviceManagerNotifyTest RegisterDeviceManagerFaCallback with parameter
 *                  4. Get checkMap from DeviceManagerNotify
 *                  5. check checkMap not null
 *                  6. call DeviceManagerNotify OnUiCall
 *                  7. check if callback OnCheckAuthResult called
 */
HWTEST_F(DeviceManagerNotifyTest, OnUiCall1, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // set dmUiCallback_ not null
    int count = 0;
    std::shared_ptr<DeviceManagerUiCallback> dmUiCallback_ = std::make_shared<DeviceManagerFaCallbackTest>(count);
    // 2. set checkMap null
    std::shared_ptr<DeviceManagerUiCallback> checkMap = nullptr;
    // 3. call DeviceManagerNotifyTest RegisterDeviceManagerFaCallback with parameter
    DeviceManagerNotify::GetInstance().RegisterDeviceManagerFaCallback(pkgName, dmUiCallback_);
    // 4. Get checkMap from DeviceManagerNotify
    checkMap = DeviceManagerNotify::GetInstance().dmUiCallback_[pkgName];
    // 5. check checkMap not null
    ASSERT_NE(checkMap, nullptr);
    // 6. call DeviceManagerNotify OnUiCall
    std::string paramJson = "trstParamJson";
    DeviceManagerNotify::GetInstance().OnUiCall(pkgName, paramJson);
    // 7. check if callback OnCheckAuthResult called
    ASSERT_EQ(count, 1);
}

/*
 * Feature: DeviceManagerNotifyTest OnUiCall
 * Function: DeviceManagerNotifyTest
 * SubFunction: OnUiCall
 * FunctionPoints: DeviceManagerNotifyTest OnUiCall
 * EnvConditions: OnUiCall success.
 * CaseDescription: 1. set pkgName not null
 *                     set dmUiCallback_ not null
 *                  2. set checkMap null
 *                  3. call DeviceManagerNotifyTest RegisterDeviceManagerFaCallback with parameter
 *                  4. Get checkMap from DeviceManagerNotify
 *                  5. check checkMap not null
 *                  6. call DeviceManagerNotify OnUiCall with testPkgName
 *                  7. check if callback OnCheckAuthResult called
 */
HWTEST_F(DeviceManagerNotifyTest, OnUiCall2, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // set dmUiCallback_ not null
    int count = 0;
    std::shared_ptr<DeviceManagerUiCallback> dmUiCallback_ = std::make_shared<DeviceManagerFaCallbackTest>(count);
    // 2. set checkMap null
    std::shared_ptr<DeviceManagerUiCallback> checkMap = nullptr;
    // 3. call DeviceManagerNotifyTest RegisterDeviceManagerFaCallback with parameter
    DeviceManagerNotify::GetInstance().RegisterDeviceManagerFaCallback(pkgName, dmUiCallback_);
    // 4. Get checkMap from DeviceManagerNotify
    checkMap = DeviceManagerNotify::GetInstance().dmUiCallback_[pkgName];
    // 5. check checkMap not null
    ASSERT_NE(checkMap, nullptr);
    // 6. call DeviceManagerNotify OnUiCall
    std::string testPkgName = "com.ohos.test1";
    std::string paramJson = "trstParamJson";
    DeviceManagerNotify::GetInstance().OnUiCall(testPkgName, paramJson);
    // 7. check if callback OnCheckAuthResult called
    ASSERT_EQ(count, 0);
}

/*
 * Feature: DeviceManagerNotifyTest OnUiCall
 * Function: DeviceManagerNotifyTest
 * SubFunction: OnUiCall
 * FunctionPoints: DeviceManagerNotifyTest OnUiCall
 * EnvConditions: OnUiCall success.
 * CaseDescription: 1. set pkgName not null
 *                     set dmUiCallback_ not null
 *                  2. set checkMap null
 *                  3. call DeviceManagerNotifyTest RegisterDeviceManagerFaCallback with parameter
 *                  4. Get checkMap from DeviceManagerNotify
 *                  5. check checkMap not null
 *                  6. call DeviceManagerNotify OnUiCall with testPkgName
 *                  7. check if callback OnCheckAuthResult called
 */
HWTEST_F(DeviceManagerNotifyTest, OnUiCall3, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // set dmUiCallback_ not null
    int count = 0;
    std::shared_ptr<DeviceManagerUiCallback> dmUiCallback_ = std::make_shared<DeviceManagerFaCallbackTest>(count);
    // 2. set checkMap null
    std::shared_ptr<DeviceManagerUiCallback> checkMap = nullptr;
    // 3. call DeviceManagerNotifyTest RegisterDeviceManagerFaCallback with parameter
    DeviceManagerNotify::GetInstance().RegisterDeviceManagerFaCallback(pkgName, dmUiCallback_);
    // 4. Get checkMap from DeviceManagerNotify
    checkMap = DeviceManagerNotify::GetInstance().dmUiCallback_[pkgName];
    // 5. check checkMap not null
    ASSERT_NE(checkMap, nullptr);
    // 6. call DeviceManagerNotify OnUiCall
    std::string testPkgName = "";
    std::string paramJson = "trstParamJson";
    DeviceManagerNotify::GetInstance().OnUiCall(testPkgName, paramJson);
    // 7. check if callback OnCheckAuthResult called
    ASSERT_EQ(count, 0);
}

/*
 * Feature: DeviceManagerNotifyTest OnUiCall
 * Function: DeviceManagerNotifyTest
 * SubFunction: OnUiCall
 * FunctionPoints: DeviceManagerNotifyTest OnUiCall
 * EnvConditions: OnUiCall success.
 * CaseDescription: 1. set pkgName not null
 *                     set dmUiCallback_ not null
 *                  2. set checkMap null
 *                  3. call DeviceManagerNotifyTest RegisterDeviceManagerFaCallback with parameter
 *                  4. Get checkMap from DeviceManagerNotify
 *                  5. check checkMap not null
 *                  6. call DeviceManagerNotify OnUiCall with testPkgName
 *                  7. check if callback OnCheckAuthResult called
 */
HWTEST_F(DeviceManagerNotifyTest, OnUiCall4, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // set dmUiCallback_ not null
    int count = 0;
    std::shared_ptr<DeviceManagerUiCallback> dmUiCallback_ = std::make_shared<DeviceManagerFaCallbackTest>(count);
    // 2. set checkMap null
    std::shared_ptr<DeviceManagerUiCallback> checkMap = nullptr;
    // 3. call DeviceManagerNotifyTest RegisterDeviceManagerFaCallback with parameter
    DeviceManagerNotify::GetInstance().RegisterDeviceManagerFaCallback(pkgName, dmUiCallback_);
    // 4. Get checkMap from DeviceManagerNotify
    checkMap = DeviceManagerNotify::GetInstance().dmUiCallback_[pkgName];
    // 5. check checkMap not null
    ASSERT_NE(checkMap, nullptr);
    // 6. call DeviceManagerNotify OnUiCall
    std::string testPkgName = "com.ohos.test";
    std::string paramJson = "trstParamJson";
    DeviceManagerNotify::GetInstance().OnUiCall(testPkgName, paramJson);
    // 7. check if callback OnCheckAuthResult called
    ASSERT_EQ(count, 1);
}

/*
 * Feature: DeviceManagerNotifyTest OnUiCall
 * Function: DeviceManagerNotifyTest
 * SubFunction: OnUiCall
 * FunctionPoints: DeviceManagerNotifyTest OnUiCall
 * EnvConditions: OnUiCall success.
 * CaseDescription: 1. set pkgName not null
 *                     set dmUiCallback_ not null
 *                  2. set checkMap null
 *                  3. call DeviceManagerNotifyTest RegisterDeviceManagerFaCallback with parameter
 *                  4. Get checkMap from DeviceManagerNotify
 *                  5. check checkMap not null
 *                  6. call DeviceManagerNotify OnUiCall with testPkgName
 *                  7. check if callback OnCheckAuthResult called
 */
HWTEST_F(DeviceManagerNotifyTest, OnUiCall5, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "";
    // set dmUiCallback_ not null
    int count = 0;
    std::shared_ptr<DeviceManagerUiCallback> dmUiCallback_ = std::make_shared<DeviceManagerFaCallbackTest>(count);
    // 2. set checkMap null
    std::shared_ptr<DeviceManagerUiCallback> checkMap = nullptr;
    // 3. call DeviceManagerNotifyTest RegisterDeviceManagerFaCallback with parameter
    DeviceManagerNotify::GetInstance().RegisterDeviceManagerFaCallback(pkgName, dmUiCallback_);
    // 4. Get checkMap from DeviceManagerNotify
    checkMap = DeviceManagerNotify::GetInstance().dmUiCallback_[pkgName];
    // 5. check checkMap not null
    ASSERT_NE(checkMap, nullptr);
    // 6. call DeviceManagerNotify OnUiCall
    std::string testPkgName = "";
    DeviceManagerNotify::GetInstance().UnRegisterDeviceManagerFaCallback(testPkgName);
    std::string paramJson = "trstParamJson";
    DeviceManagerNotify::GetInstance().OnUiCall(testPkgName, paramJson);
    // 7. check if callback OnCheckAuthResult called
    ASSERT_EQ(count, 0);
}

/**
 * @tc.name: OnCredentialResult1
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerNotifyTest, OnCredentialResult1, testing::ext::TestSize.Level0)
{
    std::string pkgName = "";
    int32_t action = 1;
    std::string credentialResult = "failed";
    DeviceManagerNotify::GetInstance().OnCredentialResult(pkgName, action, credentialResult);
    std::shared_ptr<CredentialCallback> tempCbk;
    tempCbk = DeviceManagerNotify::GetInstance().credentialCallback_[pkgName];
    EXPECT_EQ(tempCbk, nullptr);
}
/**
 * @tc.name: OnCredentialResult2
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerNotifyTest, OnCredentialResult2, testing::ext::TestSize.Level0)
{
    std::string pkgName = "com.ohos.test";
    int32_t action = 1;
    std::string credentialResult = "failed";
    std::shared_ptr<CredentialCallback> tempCbk = std::make_shared<CredentialCallbackTest>();
    DeviceManagerNotify::GetInstance().credentialCallback_[pkgName] = tempCbk;
    DeviceManagerNotify::GetInstance().OnCredentialResult(pkgName, action, credentialResult);
    int count = DeviceManagerNotify::GetInstance().credentialCallback_.count(pkgName);
    EXPECT_EQ(count, 1);
}

/**
 * @tc.name: OnCredentialResult3
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerNotifyTest, OnCredentialResult3, testing::ext::TestSize.Level0)
{
    std::string pkgName = "com.ohos.test3";
    int32_t action = 1;
    std::string credentialResult = "failed";
    DeviceManagerNotify::GetInstance().credentialCallback_[pkgName] = nullptr;
    DeviceManagerNotify::GetInstance().OnCredentialResult(pkgName, action, credentialResult);
    int count = DeviceManagerNotify::GetInstance().credentialCallback_.count(pkgName);
    EXPECT_EQ(count, 1);
}

/**
 * @tc.name: OnCredentialResult4
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerNotifyTest, OnCredentialResult4, testing::ext::TestSize.Level0)
{
    std::string pkgName = "com.ohos.test4";
    int32_t action = 1;
    std::string credentialResult = "failed";
    DeviceManagerNotify::GetInstance().OnCredentialResult(pkgName, action, credentialResult);
    int count = DeviceManagerNotify::GetInstance().credentialCallback_.count(pkgName);
    EXPECT_EQ(count, 0);
}

/**
 * @tc.name: UnRegisterDeviceStatusCallback1
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerNotifyTest, UnRegisterDeviceStatusCallback1, testing::ext::TestSize.Level0)
{
    std::string pkgName = "com.ohos.test4";
    DeviceManagerNotify::GetInstance().UnRegisterDeviceStatusCallback(pkgName);
    EXPECT_EQ(DeviceManagerNotify::GetInstance().deviceStatusCallback_.empty(), true);
}

/**
 * @tc.name: UnRegisterDeviceStatusCallback2
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerNotifyTest, UnRegisterDeviceStatusCallback2, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    DeviceManagerNotify::GetInstance().UnRegisterDeviceStatusCallback(pkgName);
    EXPECT_EQ(DeviceManagerNotify::GetInstance().deviceStatusCallback_.empty(), true);
}

/**
 * @tc.name: RegisterDeviceStatusCallback1
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerNotifyTest, RegisterDeviceStatusCallback1, testing::ext::TestSize.Level0)
{
    std::string pkgName = "com.ohos.test4";
    std::shared_ptr<DeviceStatusCallback> callback = std::make_shared<DeviceStatusCallbackTest>();
    DeviceManagerNotify::GetInstance().RegisterDeviceStatusCallback(pkgName, callback);
    EXPECT_EQ(DeviceManagerNotify::GetInstance().deviceStatusCallback_.empty(), false);
}

/**
 * @tc.name: RegisterDeviceStatusCallback2
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerNotifyTest, RegisterDeviceStatusCallback2, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    std::shared_ptr<DeviceStatusCallback> callback = std::make_shared<DeviceStatusCallbackTest>();
    DeviceManagerNotify::GetInstance().RegisterDeviceStatusCallback(pkgName, callback);
    EXPECT_EQ(DeviceManagerNotify::GetInstance().deviceStatusCallback_.empty(), false);
    DeviceManagerNotify::GetInstance().deviceStatusCallback_.clear();
}

/**
 * @tc.name: OnDeviceOnline1
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerNotifyTest, OnDeviceOnline1, testing::ext::TestSize.Level0)
{
    std::string pkgName = "com.ohos.test4";
    DmDeviceBasicInfo deviceBasicInfo;
    DeviceManagerNotify::GetInstance().OnDeviceOnline(pkgName, deviceBasicInfo);
    auto ptr = DeviceManagerNotify::GetInstance().deviceStatusCallback_[pkgName];
    EXPECT_EQ(ptr, nullptr);
}

/**
 * @tc.name: OnDeviceOnline2
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerNotifyTest, OnDeviceOnline2, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    DmDeviceBasicInfo deviceBasicInfo;
    DeviceManagerNotify::GetInstance().OnDeviceOnline(pkgName, deviceBasicInfo);
    auto ptr = DeviceManagerNotify::GetInstance().deviceStatusCallback_[pkgName];
    EXPECT_EQ(ptr, nullptr);
}

/**
 * @tc.name: OnDeviceOffline1
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerNotifyTest, OnDeviceOffline1, testing::ext::TestSize.Level0)
{
    std::string pkgName = "com.ohos.test4";
    DmDeviceBasicInfo deviceBasicInfo;
    DeviceManagerNotify::GetInstance().OnDeviceOffline(pkgName, deviceBasicInfo);
    auto ptr = DeviceManagerNotify::GetInstance().deviceStatusCallback_[pkgName];
    EXPECT_EQ(ptr, nullptr);
}

/**
 * @tc.name: OnDeviceOffline2
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerNotifyTest, OnDeviceOffline2, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    DmDeviceBasicInfo deviceBasicInfo;
    DeviceManagerNotify::GetInstance().OnDeviceOffline(pkgName, deviceBasicInfo);
    auto ptr = DeviceManagerNotify::GetInstance().deviceStatusCallback_[pkgName];
    EXPECT_EQ(ptr, nullptr);
}

/**
 * @tc.name: OnDeviceReady1
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerNotifyTest, OnDeviceReady1, testing::ext::TestSize.Level0)
{
    std::string pkgName = "com.ohos.test4";
    DmDeviceBasicInfo deviceBasicInfo;
    DeviceManagerNotify::GetInstance().OnDeviceReady(pkgName, deviceBasicInfo);
    auto ptr = DeviceManagerNotify::GetInstance().deviceStatusCallback_[pkgName];
    EXPECT_EQ(ptr, nullptr);
}

/**
 * @tc.name: OnDeviceReady2
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerNotifyTest, OnDeviceReady2, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    DmDeviceBasicInfo deviceBasicInfo;
    DeviceManagerNotify::GetInstance().OnDeviceReady(pkgName, deviceBasicInfo);
    auto ptr = DeviceManagerNotify::GetInstance().deviceStatusCallback_[pkgName];
    EXPECT_EQ(ptr, nullptr);
}

/**
 * @tc.name: OnDeviceFound6
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerNotifyTest, OnDeviceFound6, testing::ext::TestSize.Level0)
{
    std::string pkgName = "com.ohos.test4";
    uint16_t subscribeId = 0;
    DmDeviceBasicInfo deviceBasicInfo;
    DeviceManagerNotify::GetInstance().OnDeviceFound(pkgName, subscribeId, deviceBasicInfo);
    auto map = DeviceManagerNotify::GetInstance().deviceDiscoveryCallbacks_[pkgName];
    EXPECT_EQ(map.empty(), true);
}

/**
 * @tc.name: OnDeviceFound7
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerNotifyTest, OnDeviceFound7, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    uint16_t subscribeId = 0;
    DmDeviceBasicInfo deviceBasicInfo;
    DeviceManagerNotify::GetInstance().OnDeviceFound(pkgName, subscribeId, deviceBasicInfo);
    auto map = DeviceManagerNotify::GetInstance().deviceDiscoveryCallbacks_[pkgName];
    EXPECT_EQ(map.empty(), false);
}
} // namespace

DmInitCallbackTest::DmInitCallbackTest(int &count) : DmInitCallback()
{
    count_ = &count;
}
void DmInitCallbackTest::OnRemoteDied()
{
    *count_ = *count_ + 1;
}

DeviceStateCallbackTest::DeviceStateCallbackTest(int &count) : DeviceStateCallback()
{
    count_ = &count;
}

void DeviceStateCallbackTest::OnDeviceOnline(const DmDeviceInfo &deviceInfo)
{
    *count_ = *count_ + 1;
}

void DeviceStateCallbackTest::OnDeviceReady(const DmDeviceInfo &deviceInfo)
{
    *count_ = *count_ + 1;
}

void DeviceStateCallbackTest::OnDeviceOffline(const DmDeviceInfo &deviceInfo)
{
    *count_ = *count_ + 1;
}

void DeviceStateCallbackTest::OnDeviceChanged(const DmDeviceInfo &deviceInfo)
{
    *count_ = *count_ + 1;
}

DiscoveryCallbackTest::DiscoveryCallbackTest(int &count) : DiscoveryCallback()
{
    count_ = &count;
}

void DiscoveryCallbackTest::OnDeviceFound(uint16_t subscribeId, const DmDeviceInfo &deviceInfo)
{
    *count_ = *count_ + 1;
}

void DiscoveryCallbackTest::OnDiscoveryFailed(uint16_t subscribeId, int32_t failedReason)
{
    *count_ = *count_ + 1;
}

void DiscoveryCallbackTest::OnDiscoverySuccess(uint16_t subscribeId)
{
    *count_ = *count_ + 1;
}

PublishCallbackTest::PublishCallbackTest(int &count) : PublishCallback()
{
    count_ = &count;
}

void PublishCallbackTest::OnPublishResult(int32_t publishId, int32_t failedReason)
{
    *count_ = *count_ + 1;
}

AuthenticateCallbackTest::AuthenticateCallbackTest(int &count) : AuthenticateCallback()
{
    count_ = &count;
}

void AuthenticateCallbackTest::OnAuthResult(const std::string &deviceId, const std::string &token, int32_t status,
    int32_t reason)
{
    *count_ = *count_ + 1;
}

DeviceManagerFaCallbackTest::DeviceManagerFaCallbackTest(int &count) : DeviceManagerUiCallback()
{
    count_ = &count;
}

void DeviceManagerFaCallbackTest::OnCall(const std::string &paramJson)
{
    *count_ = *count_ + 1;
}
} // namespace DistributedHardware
} // namespace OHOS
