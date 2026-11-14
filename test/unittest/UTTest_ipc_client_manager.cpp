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

#include "UTTest_ipc_client_manager.h"

#include <chrono>
#include <thread>
#include "device_manager_ipc_interface_code.h"
#include "device_manager_notify.h"
#include "dm_device_info.h"
#include "dm_system_ability_manager_mock.h"
#include "ipc_client_stub.h"
#include "ipc_register_listener_req.h"
#include "ipc_remote_broker.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#include "system_ability_manager_client_mock.h"
#include "dm_constants.h"
#include "system_ability_definition.h"
#include "system_ability_load_callback_stub.h"

#include <unistd.h>

namespace OHOS {
namespace DistributedHardware {
void IpcClientManagerTest::SetUp()
{
}

void IpcClientManagerTest::TearDown()
{
}

void IpcClientManagerTest::SetUpTestCase()
{
}

void IpcClientManagerTest::TearDownTestCase()
{
}

namespace {
constexpr int32_t SHORT_DELAY_MS = 200;
    /**
 * @tc.name: OnRemoteDied_001
 * @tc.desc: 1. new a dmInterface
 *           2. set IpcClientManager dmInterface_ not null
 *           3. call ClientInit
 *           4. check ret is DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, OnRemoteDied_001, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // set dmInitCallback not null
    int count = 0;
    std::shared_ptr<DmInitCallback> dmInitCallback = std::make_shared<DmInitCallbackTest>(count);
    // 2. set checkMap null
    std::shared_ptr<DmInitCallback> checkMap = nullptr;
    // 3. call DeviceManagerNotifyTest RegisterDeathRecipientCallback with parameter
    DeviceManagerNotify::GetInstance().RegisterDeathRecipientCallback(pkgName, dmInitCallback);
    // 4. Get checkMap from DeviceManagerNotify
    checkMap = DeviceManagerNotify::GetInstance().dmInitCallback_[pkgName];
    // 5. check checkMap not null
    ASSERT_NE(checkMap, nullptr);
    // 6. call DeviceManagerNotify OnRemoteDied
    DeviceManagerNotify::GetInstance().OnRemoteDied();
    // 7. check if dmInitCallback OnRemoteDied called
    ASSERT_EQ(count, 1);
}

/**
 * @tc.name: ClientInit_001
 * @tc.desc: 1. new a dmInterface
 *           2. set IpcClientManager dmInterface_ not null
 *           3. call ClientInit
 *           4. check ret is not ERR_DM_FAILED
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, ClientInit_001, testing::ext::TestSize.Level0)
{
    // 1. new a dmInterface
    sptr<IpcRemoteBroker> dmInterface = sptr<IpcClientStub>(new IpcClientStub());
    // 2. set IpcClientManager dmInterface_ not null
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = dmInterface;
    // 3. call ClientInit
    int ret = instance->ClientInit();
    // 4. check ret is not ERR_DM_FAILED
    ASSERT_NE(ret, ERR_DM_FAILED);
}

/**
 * @tc.name: ClientInit_002
 * @tc.desc: 1. new a dmInterface
 *           2. set IpcClientManager dmInterface_ not null
 *           3. call ClientInit
 *           4. check ret is not ERR_DM_FAILED
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, ClientInit_002, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    // 3. call ClientInit
    int ret = instance->ClientInit();
    // 4. check ret is not ERR_DM_FAILED
    ASSERT_NE(ret, ERR_DM_FAILED);
}

/**
 * @tc.name: ClientInit_003
 * @tc.desc: 1. mock samgr so DM SA is null before LoadDMService, then available after
 *           2. set IpcClientManager dmInterface_ null (triggers ClientInit full path)
 *           3. call ClientInit
 *           4. check ret is DM_OK and dmInterface_ is set
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, ClientInit_003, testing::ext::TestSize.Level0)
{
    // 1. mock samgr: first CheckSystemAbility returns nullptr (trigger LoadDMService),
    //    then returns a valid object (re-check succeeds after load)
    auto clientMock = std::static_pointer_cast<SystemAbilityManagerClientMock>(
        ISystemAbilityManagerClient::GetOrCreateSAMgrClient());
    auto mockAbilityMgr = sptr<SystemAbilityManagerMock>(new SystemAbilityManagerMock());
    EXPECT_CALL(*clientMock, GetSystemAbilityManager()).WillRepeatedly(testing::Return(mockAbilityMgr));
    sptr<IRemoteObject> stubObj = sptr<IpcClientStub>(new IpcClientStub());
    EXPECT_CALL(*mockAbilityMgr, CheckSystemAbility(testing::_))
        .WillOnce(testing::Return(nullptr))
        .WillOnce(testing::Return(stubObj));
    EXPECT_CALL(*mockAbilityMgr, LoadSystemAbility(testing::_, testing::An<const sptr<ISystemAbilityLoadCallback>&>()))
        .WillOnce(testing::Invoke([](int32_t, const sptr<ISystemAbilityLoadCallback> &callback) {
            // simulate async load success by invoking the callback
            std::thread([callback]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(SHORT_DELAY_MS));
                callback->OnLoadSystemAbilitySuccess(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID, nullptr);
            }).detach();
            return DM_OK;
        }));

    // 2. set IpcClientManager dmInterface_ null (triggers ClientInit full path)
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = nullptr;
    // 3. call ClientInit
    int ret = instance->ClientInit();
    // 4. check ret is DM_OK and dmInterface_ is set
    ASSERT_EQ(ret, DM_OK);
    ASSERT_NE(instance->dmInterface_, nullptr);

    ISystemAbilityManagerClient::ReleaseSAMgrClient();
}

/**
 * @tc.name: Init_001
 * @tc.desc: 1. new a listener
 *           2. set a pkgName not null
 *           3. add listener and pkgName in dmListener_ Map
 *           4. call Init with pkgName
 *           5. check ret is not ERR_DM_FAILED
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, Init_001, testing::ext::TestSize.Level0)
{
    // 1. new a listener
    sptr<IpcClientStub> listener = sptr<IpcClientStub>(new IpcClientStub());
    // 2. set a pkgName not null
    std::string pkgName = "com.ohos.test";
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    // 3. add listener and pkgName in dmListener_ Map
    instance->dmListener_[pkgName] = listener;
    // 4. call Init with pkgName
    int32_t ret = instance->Init(pkgName);
    // 5. check ret is not ERR_DM_FAILED
    ASSERT_NE(ret, ERR_DM_FAILED);
}

/**
 * @tc.name: Init_002
 * @tc.desc: 1. set pkcName not null
 *           2. Mock IpcClientServerProxy SendCmd return ERR_DM_FAILED
 *           3. call Init with pkgName
 *           4. check ret is ERR_DM_FAILED
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, Init_002, testing::ext::TestSize.Level0)
{
    // 1. set pkcName not null
    std::string pkgName = "com.ohos.test";
    // 2. Mock IpcClientServerProxy SendCmd return ERR_DM_FAILED
    sptr<IRemoteObject> remoteObject = nullptr;
    auto mockInstance = new MockIpcClientManager(remoteObject);
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = mockInstance;
    EXPECT_CALL(*mockInstance, SendCmd(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(ERR_DM_FAILED));
    // 3. call Init with pkgName
    int32_t ret = instance->Init(pkgName);
    // 4. check ret is ERR_DM_FAILED
    ASSERT_EQ(ret, ERR_DM_FAILED);
}

/**
 * @tc.name: Init_003
 * @tc.desc: 1. set pkcName not null
 *           2. Mock IpcClientServerProxy SendCmd return DM_OK
 *           3. call Init with pkgName
 *           4. check ret is DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, Init_003, testing::ext::TestSize.Level0)
{
    // 1. set pkcName not null
    std::string pkgName = "com.ohos.test";
    // 2. Mock IpcClientServerProxy SendCmd return DM_OK
    sptr<IRemoteObject> remoteObject = nullptr;
    auto mockInstance = new MockIpcClientManager(remoteObject);
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = mockInstance;
    EXPECT_CALL(*mockInstance, SendCmd(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(DM_OK));
    // 3. call Init with pkgName
    int32_t ret = instance->Init(pkgName);
    // 4. check ret is DM_OK
    ASSERT_EQ(ret, DM_OK);
}

/**
 * @tc.name: Init_004
 * @tc.desc: 1. set pkcName not null
 *           2. Mock IpcClientServerProxy SendCmd return DM_OK
 *           3. call Init with pkgName
 *           4. check ret is DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, Init_004, testing::ext::TestSize.Level0)
{
    // 1. set pkcName not null
    std::string pkgName = "com.ohos.test";
    // 2. Mock IpcClientServerProxy SendCmd return DEVICEMANAGER_SERVICE_NOT_READY
    sptr<IRemoteObject> remoteObject = nullptr;
    auto mockInstance = new MockIpcClientManager(remoteObject);
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = mockInstance;
    EXPECT_CALL(*mockInstance, SendCmd(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(ERR_DM_INIT_FAILED));
    // 3. call Init with pkgName
    int32_t ret = instance->Init(pkgName);
    // 4. check ret is DEVICEMANAGER_OK
    ASSERT_NE(ret, DM_OK);
}

/**
 * @tc.name: Init_005
 * @tc.desc:  1. set pkcName not null
 *            2. Mock IpcClientServerProxy SendCmd return ERR_DM_IPC_RESPOND_FAILED
 *            3. call Init with pkgName
 *            4. check ret is ERR_DM_IPC_RESPOND_FAILED
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, Init_005, testing::ext::TestSize.Level0)
{
    // 1. set pkcName not null
    std::string pkgName = "com.ohos.test";
    // 2. Mock IpcClientServerProxy SendCmd return DM_OK
    sptr<IRemoteObject> remoteObject = nullptr;
    auto mockInstance = new MockIpcClientManager(remoteObject);
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = mockInstance;
    EXPECT_CALL(*mockInstance, SendCmd(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(ERR_DM_IPC_RESPOND_FAILED));
    // 3. call Init with pkgName
    int32_t ret = instance->Init(pkgName);
    // 4. check ret is ERR_DM_IPC_RESPOND_FAILED
    ASSERT_EQ(ret, ERR_DM_IPC_RESPOND_FAILED);
}

/**
 * @tc.name: UnInit_001
 * @tc.desc:  1. set pkgName null
 *               set IpcClientManager dmInterface_ null
 *            2. call UnInit with pkgName
 *            3. check ret is ERR_DM_INPUT_PARA_INVALID
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, UnInit1, testing::ext::TestSize.Level0)
{
    // 1. set pkgName null
    std::string pkgName;
    // set IpcClientManager dmInterface_ null
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = nullptr;
    // 2. call UnInit with pkgName
    int32_t ret = instance->UnInit(pkgName);
    // 3. check ret is ERR_DM_INPUT_PARA_INVALID
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: UnInit_002
 * @tc.desc:  1. set pkgName not null
 *            2. Mock IpcClientServerProxy SendCmd return ERR_DM_FAILED
 *            3. set IpcClientManager dmInterface_ not null
 *            4. set IpcClientManager dmListener_ not null
 *            5. call UnInit with pkgName
 *            6. check ret is ERR_DM_FAILED
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, UnInit_002, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // 2. Mock IpcClientServerProxy SendCmd return ERR_DM_FAILED
    sptr<IRemoteObject> remoteObject = nullptr;
    auto mockInstance = new MockIpcClientManager(remoteObject);
    EXPECT_CALL(*mockInstance, SendCmd(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(ERR_DM_FAILED));
    // 3. set IpcClientManager dmInterface_ not null
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = mockInstance;
    // 4. set IpcClientManager dmListener_ not null
    sptr<IpcClientStub> listener = sptr<IpcClientStub>(new IpcClientStub());
    instance->dmListener_[pkgName] = listener;
    // 5. call UnInit with pkgName
    int32_t ret = instance->UnInit(pkgName);
    // 6. check ret is ERR_DM_FAILED
    ASSERT_EQ(ret, ERR_DM_FAILED);
}

/**
 * @tc.name: UnInit_003
 * @tc.desc:  1. set pkgName not null
 *            2. Mock IpcClientServerProxy SendCmd return DM_OK
 *            3. set IpcClientManager dmInterface_ not null
 *            4. set IpcClientManager dmListener_ not null
 *            5. call UnInit with pkgName
 *            6. check ret is DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, UnInit_003, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // 2. Mock IpcClientServerProxy SendCmd return DM_OK
    sptr<IRemoteObject> remoteObject = nullptr;
    auto mockInstance = new MockIpcClientManager(remoteObject);
    EXPECT_CALL(*mockInstance, SendCmd(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(DM_OK));
    // 3. set IpcClientManager dmInterface_ not null
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = mockInstance;
    // 4. set IpcClientManager dmListener_ not null
    sptr<IpcClientStub> listener = sptr<IpcClientStub>(new IpcClientStub());
    instance->dmListener_[pkgName] = listener;
    // 5. call UnInit with pkgName
    int32_t ret = instance->UnInit(pkgName);
    // 6. check ret is DM_OK
    ASSERT_EQ(ret, DM_OK);
}

/**
 * @tc.name: UnInit_004
 * @tc.desc:  1. set pkgName not null
 *            2. Mock IpcClientServerProxy SendCmd return ERR_DM_INIT_FAILED
 *            3. set IpcClientManager dmInterface_ not null
 *            4. set IpcClientManager dmListener_ not null
 *            5. call UnInit with pkgName
 *            6. check ret is ERR_DM_INIT_FAILED
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, UnInit_004, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // 2. Mock IpcClientServerProxy SendCmd return ERR_DM_INIT_FAILED
    sptr<IRemoteObject> remoteObject = nullptr;
    auto mockInstance = new MockIpcClientManager(remoteObject);
    EXPECT_CALL(*mockInstance, SendCmd(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(ERR_DM_INIT_FAILED));
    // 3. set IpcClientManager dmInterface_ not null
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = mockInstance;
    // 4. set IpcClientManager dmListener_ not null
    sptr<IpcClientStub> listener = sptr<IpcClientStub>(new IpcClientStub());
    instance->dmListener_[pkgName] = listener;
    // 5. call UnInit with pkgName
    int32_t ret = instance->UnInit(pkgName);
    // 6. check ret is ERR_DM_INIT_FAILED
    ASSERT_EQ(ret, ERR_DM_INIT_FAILED);
}

/**
 * @tc.name: UnInit_005
 * @tc.desc:  1. set pkgName not null
 *            2. Mock IpcClientServerProxy SendCmd return ERR_DM_IPC_SEND_REQUEST_FAILED
 *            3. set IpcClientManager dmInterface_ not null
 *            4. set IpcClientManager dmListener_ not null
 *            5. call UnInit with pkgName
 *            6. check ret is ERR_DM_IPC_SEND_REQUEST_FAILED
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, UnInit_005, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    // 2. Mock IpcClientServerProxy SendCmd return ERR_DM_IPC_SEND_REQUEST_FAILED
    sptr<IRemoteObject> remoteObject = nullptr;
    auto mockInstance = new MockIpcClientManager(remoteObject);
    EXPECT_CALL(*mockInstance, SendCmd(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(ERR_DM_IPC_SEND_REQUEST_FAILED));
    // 3. set IpcClientManager dmInterface_ not null
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = mockInstance;
    // 4. set IpcClientManager dmListener_ not null
    sptr<IpcClientStub> listener = sptr<IpcClientStub>(new IpcClientStub());
    instance->dmListener_[pkgName] = listener;
    // 5. call UnInit with pkgName
    int32_t ret = instance->UnInit(pkgName);
    // 6. check ret is ERR_DM_IPC_SEND_REQUEST_FAILED
    ASSERT_EQ(ret, ERR_DM_IPC_SEND_REQUEST_FAILED);
}

/**
 * @tc.name: SendRequest_001
 * @tc.desc:  1. set IpcClientManager dmInterface_ null
 *            2. call SendRequest with parameter
 *            3. dmInterface_ null triggers ClientInit re-init, DM SA still unavailable
 *            4. check ret is ERR_DM_INIT_FAILED (re-init fail, no crash/hang)
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, SendRequest_001, testing::ext::TestSize.Level0)
{
    // 0. mock samgr: DM SA unavailable so re-init always fails
    auto clientMock = std::static_pointer_cast<SystemAbilityManagerClientMock>(
        ISystemAbilityManagerClient::GetOrCreateSAMgrClient());
    auto mockAbilityMgr = sptr<SystemAbilityManagerMock>(new SystemAbilityManagerMock());
    EXPECT_CALL(*clientMock, GetSystemAbilityManager()).WillRepeatedly(testing::Return(mockAbilityMgr));
    EXPECT_CALL(*mockAbilityMgr, CheckSystemAbility(testing::_)).WillRepeatedly(testing::Return(nullptr));
    EXPECT_CALL(*mockAbilityMgr, LoadSystemAbility(testing::_, testing::An<const sptr<ISystemAbilityLoadCallback>&>()))
        .WillRepeatedly(testing::Return(ERR_DM_FAILED));

    // 1. set IpcClientManager dmInterface_ null
    std::string pkgName = "";
    std::shared_ptr<IpcReq> req = std::make_shared<IpcReq>();
    std::shared_ptr<IpcRsp> rsp = std::make_shared<IpcRsp>();
    req->SetPkgName(pkgName);
    // 2. set IpcClientManager dmInterface_ null
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = nullptr;
    // 3. call SendRequest with parameter
    int ret = instance->SendRequest(0, req, rsp);
    // 4. check ret is ERR_DM_INIT_FAILED
    ASSERT_EQ(ret, ERR_DM_INIT_FAILED);

    ISystemAbilityManagerClient::ReleaseSAMgrClient();
}

/**
 * @tc.name: SendRequest_010
 * @tc.desc:  1. mock samgr so DM SA is null before LoadDMService, then available after
 *            2. set IpcClientManager dmInterface_ null (triggers re-init)
 *            3. call SendRequest with parameter
 *            4. check re-init path is taken: dmInterface_ is set and ret is not ERR_DM_INIT_FAILED
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, SendRequest_010, testing::ext::TestSize.Level0)
{
    // 1. mock samgr: first CheckSystemAbility returns nullptr (trigger LoadDMService),
    //    then returns a valid proxy object (re-check succeeds after load)
    auto clientMock = std::static_pointer_cast<SystemAbilityManagerClientMock>(
        ISystemAbilityManagerClient::GetOrCreateSAMgrClient());
    auto mockAbilityMgr = sptr<SystemAbilityManagerMock>(new SystemAbilityManagerMock());
    EXPECT_CALL(*clientMock, GetSystemAbilityManager()).WillRepeatedly(testing::Return(mockAbilityMgr));
    sptr<IRemoteObject> stubObj = sptr<IpcClientStub>(new IpcClientStub());
    EXPECT_CALL(*mockAbilityMgr, CheckSystemAbility(testing::_))
        .WillOnce(testing::Return(nullptr))
        .WillOnce(testing::Return(stubObj));
    EXPECT_CALL(*mockAbilityMgr, LoadSystemAbility(testing::_, testing::An<const sptr<ISystemAbilityLoadCallback>&>()))
        .WillOnce(testing::Invoke([](int32_t, const sptr<ISystemAbilityLoadCallback> &callback) {
            std::thread([callback]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(SHORT_DELAY_MS));
                callback->OnLoadSystemAbilitySuccess(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID, nullptr);
            }).detach();
            return DM_OK;
        }));

    // 2. set IpcClientManager dmInterface_ null (triggers re-init)
    std::shared_ptr<IpcRegisterListenerReq> req = std::make_shared<IpcRegisterListenerReq>();
    std::shared_ptr<IpcRsp> rsp = std::make_shared<IpcRsp>();
    req->SetPkgName("com.ohos.test");
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = nullptr;
    // 3. call SendRequest with parameter
    int ret = instance->SendRequest(0, req, rsp);
    // 4. check re-init path is taken: dmInterface_ is set and ret is not ERR_DM_INIT_FAILED
    ASSERT_NE(instance->dmInterface_, nullptr);
    ASSERT_NE(ret, ERR_DM_INIT_FAILED);

    ISystemAbilityManagerClient::ReleaseSAMgrClient();
}

/**
 * @tc.name: SendRequest_002
 * @tc.desc:  1. set pkgName not null
 *            2. Mock IpcClientServerProxy SendCmd return ERR_DM_FAILED
 *            3. set IpcClientManager dmInterface_ not null
 *            4. set IpcClientManager dmListener_ not null
 *            5. call SendRequest with parameter
 *            6. check ret is ERR_DM_FAILED
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, SendRequest_002, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    std::shared_ptr<IpcReq> req = std::make_shared<IpcReq>();
    std::shared_ptr<IpcRsp> rsp = std::make_shared<IpcRsp>();
    req->SetPkgName(pkgName);
    // 2. Mock IpcClientServerProxy SendCmd return ERR_DM_FAILED
    sptr<IRemoteObject> remoteObject = nullptr;
    auto mockInstance = new MockIpcClientManager(remoteObject);
    EXPECT_CALL(*mockInstance, SendCmd(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(ERR_DM_FAILED));
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    // 3. set IpcClientManager dmInterface_ not null
    instance->dmInterface_ = mockInstance;
    sptr<IpcClientStub> listener = sptr<IpcClientStub>(new IpcClientStub());
    // 4. set IpcClientManager dmListener_ not null
    instance->dmListener_[pkgName] = listener;
    // 5. call SendRequest with parameter
    int ret = instance->SendRequest(0, req, rsp);
    // 6. check ret is ERR_DM_FAILED
    ASSERT_EQ(ret, ERR_DM_FAILED);
}

/**
 * @tc.name: SendRequest_003
 * @tc.desc:  1. set pkgName not null
 *            2. Mock IpcClientServerProxy SendCmd return DM_OK
 *            3. set IpcClientManager dmInterface_ not null
 *            4. set IpcClientManager dmListener_ not null
 *            5. call SendRequest with parameter
 *            6. check ret is DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, SendRequest_003, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    std::shared_ptr<IpcReq> req = std::make_shared<IpcReq>();
    std::shared_ptr<IpcRsp> rsp = std::make_shared<IpcRsp>();
    req->SetPkgName(pkgName);
    // 2. Mock IpcClientServerProxy SendCmd return DM_OK
    sptr<IRemoteObject> remoteObject = nullptr;
    auto mockInstance = new MockIpcClientManager(remoteObject);
    EXPECT_CALL(*mockInstance, SendCmd(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(DM_OK));
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    // 3. set IpcClientManager dmInterface_ not null
    instance->dmInterface_ = mockInstance;
    sptr<IpcClientStub> listener = sptr<IpcClientStub>(new IpcClientStub());
    // 4. set IpcClientManager dmListener_ not null
    instance->dmListener_[pkgName] = listener;
    // 5. call SendRequest with parameter
    int ret = instance->SendRequest(0, req, rsp);
    // 6. check ret is DM_OK
    ASSERT_EQ(ret, DM_OK);
}

/**
 * @tc.name: SendRequest_004
 * @tc.desc:  1. set pkgName not null
 *            2. Mock IpcClientServerProxy SendCmd return ERR_DM_INIT_FAILED
 *            3. set IpcClientManager dmInterface_ not null
 *            4. set IpcClientManager dmListener_ not null
 *            5. call SendRequest with parameter
 *            6. check ret is ERR_DM_INIT_FAILED
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, SendRequest_004, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    std::shared_ptr<IpcReq> req = std::make_shared<IpcReq>();
    std::shared_ptr<IpcRsp> rsp = std::make_shared<IpcRsp>();
    req->SetPkgName(pkgName);
    // 2. Mock IpcClientServerProxy SendCmd return ERR_DM_INIT_FAILED
    sptr<IRemoteObject> remoteObject = nullptr;
    auto mockInstance = new MockIpcClientManager(remoteObject);
    EXPECT_CALL(*mockInstance, SendCmd(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(ERR_DM_INIT_FAILED));
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    // 3. set IpcClientManager dmInterface_ not null
    instance->dmInterface_ = mockInstance;
    sptr<IpcClientStub> listener = sptr<IpcClientStub>(new IpcClientStub());
    // 4. set IpcClientManager dmListener_ not null
    instance->dmListener_[pkgName] = listener;
    // 5. call SendRequest with parameter
    int ret = instance->SendRequest(0, req, rsp);
    // 6. check ret is ERR_DM_INIT_FAILED
    ASSERT_EQ(ret, ERR_DM_INIT_FAILED);
}

/**
 * @tc.name: SendRequest_005
 * @tc.desc:  1. set pkgName not null
 *            2. Mock IpcClientServerProxy SendCmd return ERR_DM_IPC_SEND_REQUEST_FAILED
 *            3. set IpcClientManager dmInterface_ not null
 *            4. set IpcClientManager dmListener_ not null
 *            5. call SendRequest with parameter
 *            6. check ret is ERR_DM_IPC_SEND_REQUEST_FAILED
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, SendRequest_005, testing::ext::TestSize.Level0)
{
    // 1. set pkgName not null
    std::string pkgName = "com.ohos.test";
    std::shared_ptr<IpcReq> req = std::make_shared<IpcReq>();
    std::shared_ptr<IpcRsp> rsp = std::make_shared<IpcRsp>();
    req->SetPkgName(pkgName);
    // 2. Mock IpcClientServerProxy SendCmd return ERR_DM_IPC_SEND_REQUEST_FAILED
    sptr<IRemoteObject> remoteObject = nullptr;
    auto mockInstance = new MockIpcClientManager(remoteObject);
    EXPECT_CALL(*mockInstance, SendCmd(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(ERR_DM_IPC_SEND_REQUEST_FAILED));
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    // 3. set IpcClientManager dmInterface_ not null
    instance->dmInterface_ = mockInstance;
    sptr<IpcClientStub> listener = sptr<IpcClientStub>(new IpcClientStub());
    // 4. set IpcClientManager dmListener_ not null
    instance->dmListener_[pkgName] = listener;
    // 5. call SendRequest with parameter
    int ret = instance->SendRequest(0, req, rsp);
    // 6. check ret is ERR_DM_IPC_SEND_REQUEST_FAILED
    ASSERT_EQ(ret, ERR_DM_IPC_SEND_REQUEST_FAILED);
}

/**
 * @tc.name: SendRequest_006
 * @tc.type: FUNC
 */
HWTEST_F(IpcClientManagerTest, SendRequest_006, testing::ext::TestSize.Level0)
{
    std::string pkgName = "com.ohos.test";
    std::shared_ptr<IpcReq> req = std::make_shared<IpcReq>();
    std::shared_ptr<IpcRsp> rsp = std::make_shared<IpcRsp>();
    req->SetPkgName(pkgName);
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = nullptr;
    int ret = instance->SendRequest(IPC_MSG_BUTT, req, rsp);
    ASSERT_EQ(ret, ERR_DM_UNSUPPORTED_IPC_COMMAND);
}

/**
 * @tc.name: SendRequest_007
 * @tc.type: FUNC
 */
HWTEST_F(IpcClientManagerTest, SendRequest_007, testing::ext::TestSize.Level0)
{
    std::string pkgName = "com.ohos.test";
    std::shared_ptr<IpcReq> req = std::make_shared<IpcReq>();
    std::shared_ptr<IpcRsp> rsp = std::make_shared<IpcRsp>();
    req->SetPkgName(pkgName);
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = nullptr;
    int ret = instance->SendRequest(-1, req, rsp);
    ASSERT_EQ(ret, ERR_DM_UNSUPPORTED_IPC_COMMAND);
}

/**
 * @tc.name: SendRequest_008
 * @tc.type: FUNC
 */
HWTEST_F(IpcClientManagerTest, SendRequest_008, testing::ext::TestSize.Level0)
{
    std::string pkgName = "com.ohos.test";
    std::shared_ptr<IpcReq> req = nullptr;
    std::shared_ptr<IpcRsp> rsp = std::make_shared<IpcRsp>();
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = nullptr;
    int ret = instance->SendRequest(0, req, rsp);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: SendRequest_009
 * @tc.type: FUNC
 */
HWTEST_F(IpcClientManagerTest, SendRequest_009, testing::ext::TestSize.Level0)
{
    std::string pkgName = "";
    std::shared_ptr<IpcReq> req = std::make_shared<IpcReq>();
    std::shared_ptr<IpcRsp> rsp = nullptr;
    req->SetPkgName(pkgName);
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = nullptr;
    int ret = instance->SendRequest(0, req, rsp);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: OnDmServiceDied_001
 * @tc.desc: 1. set IpcClientManager dmInterface_null
 *           2. call OnDmServiceDied
 *           3. check ret is ERR_DM_POINT_NULL
 * @tc.type: FUNC
 */
HWTEST_F(IpcClientManagerTest, OnDmServiceDied_001, testing::ext::TestSize.Level0)
{
    // 1. set IpcClientManager dmInterface_null
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = nullptr;
    // 2. call OnDmServiceDied
    int32_t ret = instance->OnDmServiceDied();
    // 3. check ret is false
    ASSERT_EQ(ret, ERR_DM_POINT_NULL);
}

/**
 * @tc.name: OnDmServiceDied_002
 * @tc.desc: 1. set IpcClientManager dmInterface_null
 *           3. call OnDmServiceDied
 *           4. check ret is DM_OK
 * @tc.type: FUNC
 */
HWTEST_F(IpcClientManagerTest, OnDmServiceDied_002, testing::ext::TestSize.Level0)
{
    // 1. set IpcClientManager dmInterface_null
    sptr<IRemoteObject> remoteObject = nullptr;
    auto mockInstance = new MockIpcClientManager(remoteObject);
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = mockInstance;
    // 2. call OnDmServiceDied
    int32_t ret = instance->OnDmServiceDied();
    // 3. check ret is DM_OK
    ASSERT_EQ(ret, DM_OK);
}

/**
 * @tc.name: OnDmServiceDied_003
 * @tc.desc: 1. set IpcClientManager dmInterface_null
 *           3. call OnDmServiceDied
 *           4. check ret is DM_OK
 * @tc.type: FUNC
 */
HWTEST_F(IpcClientManagerTest, OnDmServiceDied_003, testing::ext::TestSize.Level0)
{
    // 1. set IpcClientManager dmInterface_null
    sptr<IpcRemoteBroker> dmInterface = sptr<IpcClientStub>(new IpcClientStub());
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = dmInterface;
    instance->dmRecipient_ = sptr<DmDeathRecipient>(new DmDeathRecipient());
    // 2. call OnDmServiceDied
    int32_t ret = instance->OnDmServiceDied();
    // 3. check ret is DM_OK
    ASSERT_EQ(ret, DM_OK);
}

/**
 * @tc.name: SendRequest_011
 * @tc.desc:  1. set IpcClientManager dmInterface_ not null (already init)
 *            2. mock dmInterface_ SendCmd return DM_OK
 *            3. call SendRequest with valid cmdCode
 *            4. check ret is DM_OK (no re-init path taken)
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, SendRequest_011, testing::ext::TestSize.Level0)
{
    std::string pkgName = "com.ohos.test";
    std::shared_ptr<IpcReq> req = std::make_shared<IpcReq>();
    std::shared_ptr<IpcRsp> rsp = std::make_shared<IpcRsp>();
    req->SetPkgName(pkgName);
    sptr<IRemoteObject> remoteObject = nullptr;
    auto mockInstance = new MockIpcClientManager(remoteObject);
    EXPECT_CALL(*mockInstance, SendCmd(testing::_, testing::_, testing::_))
        .Times(1).WillOnce(testing::Return(DM_OK));
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = mockInstance;
    int ret = instance->SendRequest(0, req, rsp);
    ASSERT_EQ(ret, DM_OK);
}

/**
 * @tc.name: ClientInit_004
 * @tc.desc: 1. set dmInterface_ to a valid proxy (already initialized)
 *           2. call ClientInit
 *           3. verify early return DM_OK without touching samgr
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, ClientInit_004, testing::ext::TestSize.Level0)
{
    sptr<IpcRemoteBroker> dmInterface = sptr<IpcClientStub>(new IpcClientStub());
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = dmInterface;
    int ret = instance->ClientInit();
    ASSERT_EQ(ret, DM_OK);
    ASSERT_NE(instance->dmInterface_, nullptr);
}

/**
 * @tc.name: ClientInit_005
 * @tc.desc: 1. mock samgr returning nullptr (samgr unavailable)
 *           2. set dmInterface_ null
 *           3. call ClientInit
 *           4. check ret is ERR_DM_INIT_FAILED
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, ClientInit_005, testing::ext::TestSize.Level0)
{
    auto clientMock = std::static_pointer_cast<SystemAbilityManagerClientMock>(
        ISystemAbilityManagerClient::GetOrCreateSAMgrClient());
    EXPECT_CALL(*clientMock, GetSystemAbilityManager()).WillRepeatedly(testing::Return(nullptr));

    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = nullptr;
    int ret = instance->ClientInit();
    ASSERT_EQ(ret, ERR_DM_INIT_FAILED);

    ISystemAbilityManagerClient::ReleaseSAMgrClient();
}

/**
 * @tc.name: OnDmServiceDied_004
 * @tc.desc: 1. set dmInterface_ to a valid proxy and dmRecipient_ to a valid recipient
 *           2. call OnDmServiceDied
 *           3. verify dmInterface_ is null and dmRecipient_ is null after call
 *           4. check ret is DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, OnDmServiceDied_004, testing::ext::TestSize.Level0)
{
    sptr<IRemoteObject> remoteObject = sptr<IpcClientStub>(new IpcClientStub());
    auto mockInstance = new MockIpcClientManager(remoteObject);
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = mockInstance;
    instance->dmRecipient_ = sptr<DmDeathRecipient>(new DmDeathRecipient());
    int32_t ret = instance->OnDmServiceDied();
    ASSERT_EQ(ret, DM_OK);
    ASSERT_EQ(instance->dmInterface_, nullptr);
    ASSERT_EQ(instance->dmRecipient_, nullptr);
}

/**
 * @tc.name: ClientInit_006
 * @tc.desc: 1. mock samgr so DM SA is null, LoadDMService fails, re-check still null
 *           2. set dmInterface_ null
 *           3. call ClientInit
 *           4. verify ret is ERR_DM_INIT_FAILED
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, ClientInit_006, testing::ext::TestSize.Level0)
{
    auto clientMock = std::static_pointer_cast<SystemAbilityManagerClientMock>(
        ISystemAbilityManagerClient::GetOrCreateSAMgrClient());
    auto mockAbilityMgr = sptr<SystemAbilityManagerMock>(new SystemAbilityManagerMock());
    EXPECT_CALL(*clientMock, GetSystemAbilityManager()).WillRepeatedly(testing::Return(mockAbilityMgr));
    EXPECT_CALL(*mockAbilityMgr, CheckSystemAbility(testing::_)).WillRepeatedly(testing::Return(nullptr));
    EXPECT_CALL(*mockAbilityMgr, LoadSystemAbility(testing::_, testing::An<const sptr<ISystemAbilityLoadCallback>&>()))
        .WillRepeatedly(testing::Return(ERR_DM_FAILED));

    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = nullptr;
    int ret = instance->ClientInit();
    ASSERT_EQ(ret, ERR_DM_INIT_FAILED);

    ISystemAbilityManagerClient::ReleaseSAMgrClient();
}

/**
 * @tc.name: SendRequest_012
 * @tc.desc:  1. set IpcClientManager dmInterface_ null
 *            2. mock samgr so DM SA is null, LoadSystemAbility succeeds and callback fires
 *            3. re-check SA available (returns stub object)
 *            4. call SendRequest with valid cmdCode
 *            5. verify re-init path taken: dmInterface_ is set, ret is not ERR_DM_INIT_FAILED
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, SendRequest_012, testing::ext::TestSize.Level0)
{
    auto clientMock = std::static_pointer_cast<SystemAbilityManagerClientMock>(
        ISystemAbilityManagerClient::GetOrCreateSAMgrClient());
    auto mockAbilityMgr = sptr<SystemAbilityManagerMock>(new SystemAbilityManagerMock());
    EXPECT_CALL(*clientMock, GetSystemAbilityManager()).WillRepeatedly(testing::Return(mockAbilityMgr));
    sptr<IRemoteObject> stubObj = sptr<IpcClientStub>(new IpcClientStub());
    EXPECT_CALL(*mockAbilityMgr, CheckSystemAbility(testing::_))
        .WillOnce(testing::Return(nullptr))
        .WillOnce(testing::Return(stubObj));
    EXPECT_CALL(*mockAbilityMgr, LoadSystemAbility(testing::_, testing::An<const sptr<ISystemAbilityLoadCallback>&>()))
        .WillOnce(testing::Invoke([](int32_t, const sptr<ISystemAbilityLoadCallback> &callback) {
            std::thread([callback]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(SHORT_DELAY_MS));
                callback->OnLoadSystemAbilitySuccess(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID, nullptr);
            }).detach();
            return DM_OK;
        }));

    std::shared_ptr<IpcRegisterListenerReq> req = std::make_shared<IpcRegisterListenerReq>();
    std::shared_ptr<IpcRsp> rsp = std::make_shared<IpcRsp>();
    req->SetPkgName("com.ohos.test");
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = nullptr;
    int ret = instance->SendRequest(REGISTER_DEVICE_MANAGER_LISTENER, req, rsp);
    ASSERT_NE(instance->dmInterface_, nullptr);
    ASSERT_NE(ret, ERR_DM_INIT_FAILED);

    ISystemAbilityManagerClient::ReleaseSAMgrClient();
}

/**
 * @tc.name: OnDmServiceDied_005
 * @tc.desc: 1. set dmInterface_ to a real IpcClientStub and dmRecipient_ to nullptr
 *           2. call OnDmServiceDied
 *           3. verify ret is DM_OK and dmInterface_ is null
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, OnDmServiceDied_005, testing::ext::TestSize.Level0)
{
    sptr<IpcRemoteBroker> dmInterface = sptr<IpcClientStub>(new IpcClientStub());
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = dmInterface;
    instance->dmRecipient_ = nullptr;
    int32_t ret = instance->OnDmServiceDied();
    ASSERT_EQ(ret, DM_OK);
    ASSERT_EQ(instance->dmInterface_, nullptr);
}

/**
 * @tc.name: SendRequest_013
 * @tc.desc:  1. set IpcClientManager dmInterface_ null
 *            2. mock samgr so GetSystemAbilityManager returns null
 *            3. call SendRequest with valid cmdCode
 *            4. verify ret is ERR_DM_INIT_FAILED (samgr null, re-init fails immediately)
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcClientManagerTest, SendRequest_013, testing::ext::TestSize.Level0)
{
    auto clientMock = std::static_pointer_cast<SystemAbilityManagerClientMock>(
        ISystemAbilityManagerClient::GetOrCreateSAMgrClient());
    EXPECT_CALL(*clientMock, GetSystemAbilityManager()).WillRepeatedly(testing::Return(nullptr));

    std::shared_ptr<IpcReq> req = std::make_shared<IpcReq>();
    std::shared_ptr<IpcRsp> rsp = std::make_shared<IpcRsp>();
    req->SetPkgName("com.ohos.test");
    std::shared_ptr<IpcClientManager> instance = std::make_shared<IpcClientManager>();
    instance->dmInterface_ = nullptr;
    int ret = instance->SendRequest(0, req, rsp);
    ASSERT_EQ(ret, ERR_DM_INIT_FAILED);

    ISystemAbilityManagerClient::ReleaseSAMgrClient();
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
} // namespace DistributedHardware
} // namespace OHOS
