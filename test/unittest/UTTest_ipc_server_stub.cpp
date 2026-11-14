/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "UTTest_ipc_server_stub.h"

#include <algorithm>
#include <thread>
#include <unistd.h>

#include "device_manager_ipc_interface_code.h"
#include "device_manager_service.h"
#include "dm_device_info.h"
#include "ipc_remote_broker.h"
#include "ipc_server_stub.h"
#include "device_manager_impl.h"
#include "dm_constants.h"
#include "if_system_ability_manager.h"
#include "ipc_cmd_register.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DistributedHardware {
void IpcServerStubTest::SetUp()
{
}

void IpcServerStubTest::TearDown()
{
}

void IpcServerStubTest::SetUpTestCase()
{
}

void IpcServerStubTest::TearDownTestCase()
{
}

namespace {
/**
 * @tc.name: OnStop_001
 * @tc.desc: 1. Call IpcServerStub OnStop
 *           2. check IpcServerStub.state is ServiceRunningState::STATE_RUNNING
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, OnStop_001, testing::ext::TestSize.Level0)
{
    // 1. Call IpcServerStub OnStop
    IpcServerStub::GetInstance().OnStop();
    // 2. check IpcServerStub.state is ServiceRunningState::STATE_RUNNING
    ASSERT_EQ(ServiceRunningState::STATE_NOT_START, IpcServerStub::GetInstance().state_);
    ASSERT_EQ(IpcServerStub::GetInstance().registerToService_, false);
}

/**
 * @tc.name: OnStart_001
 * @tc.desc: 1. set IpcServerStub state is ServiceRunningState::STATE_RUNNING
 *           2. Call IpcServerStub OnStart
 *           3. check IpcServerStub.state is ServiceRunningState::STATE_RUNNING
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, OnStart_001, testing::ext::TestSize.Level0)
{
    // 1. set IpcServerStub state is ServiceRunningState::STATE_RUNNING
    IpcServerStub::GetInstance().state_ = ServiceRunningState::STATE_RUNNING;
    // 2. Call IpcServerStub OnStart
    IpcServerStub::GetInstance().OnStart();
    // 3. check IpcServerStub.state is ServiceRunningState::STATE_RUNNING
    ASSERT_EQ(ServiceRunningState::STATE_RUNNING, IpcServerStub::GetInstance().state_);
}

/**
 * @tc.name: OnStart_002
 * @tc.desc:  1. Set initial state to STATE_NOT_START
 *            2. Call OnStart to start the service
 *            3. Call OnStop to stop the service
 *            4. Check the final state is STATE_NOT_START
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, OnStart_002, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().state_ = ServiceRunningState::STATE_NOT_START;
    IpcServerStub::GetInstance().OnStart();
    IpcServerStub::GetInstance().OnStop();
    ASSERT_EQ(ServiceRunningState::STATE_NOT_START, IpcServerStub::GetInstance().state_);
}

/**
 * @tc.name: Init_001
 * @tc.desc: 1. Call IpcServerStub OnStart
 *           2. check IpcServerStub.state is ServiceRunningState::STATE_RUNNING
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, Init_001, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().registerToService_=true;
    bool result = IpcServerStub::GetInstance().Init();
    // 2. check IpcServerStub.state is ServiceRunningState::STATE_RUNNING
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: OnRemoteRequest_001
 * @tc.desc: 1. Set Code = 999
 *           2. Call IpcServerStub OnRemoteRequest with param
 *           3. check ret not DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, OnRemoteRequest_001, testing::ext::TestSize.Level0)
{
    // 1. Set Code = 999
    uint32_t code = 999;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int ret = 0;
    // 2. Call IpcServerStub OnRemoteRequest with param
    ret = IpcServerStub::GetInstance().OnRemoteRequest(code, data, reply, option);
    // 3. check ret not DM_OK
    ASSERT_NE(ret, DM_OK);
}

/**
 * @tc.name: OnRemoteRequest_002
 * @tc.desc: 1. Set Code = 999
 *           2. Call IpcServerStub OnRemoteRequest with param
 *           3. check ret not DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, OnRemoteRequest_002, testing::ext::TestSize.Level0)
{
    // 1. Set Code is SERVER_DEVICE_STATE_NOTIFY
    uint32_t code = SERVER_DEVICE_STATE_NOTIFY;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int ret = 0;
    // 2. Call IpcServerStub OnRemoteRequest with param
    ret = IpcServerStub::GetInstance().OnRemoteRequest(code, data, reply, option);
    // 3. check ret not DM_OK
    ASSERT_NE(ret, DM_OK);
}

/**
 * @tc.name: SendCmd_001
 * @tc.desc: 1. Call IpcServerStub SendCmd
 *           2. check ret is DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, SendCmd_001, testing::ext::TestSize.Level0)
{
    int result = 305;
    int32_t cmdCode = -1;
    std::shared_ptr<IpcReq> req = std::make_shared<IpcReq>();
    std::shared_ptr<IpcRsp> rsp = std::make_shared<IpcRsp>();
    // 1. Call IpcServerStub SendCmd
    int32_t ret = IpcServerStub::GetInstance().SendCmd(cmdCode, req, rsp);
    // 2. check ret is DM_OK
    ASSERT_EQ(ret, result);
}

/**
 * @tc.name: SendCmd_002
 * @tc.desc: 1. Call IpcServerStub SendCmd
 *           2. check ret is ERR_DM_INPUT_PARA_INVALID
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, SendCmd_002, testing::ext::TestSize.Level0)
{
    int result = 305;
    int32_t cmdCode = IPC_MSG_BUTT;
    std::shared_ptr<IpcReq> req = std::make_shared<IpcReq>();
    std::shared_ptr<IpcRsp> rsp = std::make_shared<IpcRsp>();
    // 1. Call IpcServerStub SendCmd
    int32_t ret = IpcServerStub::GetInstance().SendCmd(cmdCode, req, rsp);
    // 2. check ret is DM_OK
    ASSERT_EQ(ret, result);
}

/**
 * @tc.name: QueryServiceState_001
 * @tc.desc: 1. Call IpcServerStub QueryServiceState
 *           2. check IpcServerStub.state is ServiceRunningState::STATE_RUNNING
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, QueryServiceState_001, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().state_ = ServiceRunningState::STATE_NOT_START;
    // 1. Call IpcServerStub QueryServiceState
    ServiceRunningState state = IpcServerStub::GetInstance().QueryServiceState();
    // 2. check IpcServerStub.state is ServiceRunningState::STATE_RUNNING
    ASSERT_EQ(state, ServiceRunningState::STATE_NOT_START);
}

/**
 * @tc.name: RegisterDeviceManagerListener_001
 * @tc.desc: 1. Call IpcServerStub RegisterDeviceManagerListener
 *           2. check IpcServerStub.state is ServiceRunningState::STATE_RUNNING
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, RegisterDeviceManagerListener_001, testing::ext::TestSize.Level0)
{
    std::string pkgName = "";
    ProcessInfo processInfo;
    processInfo.pkgName = pkgName;
    processInfo.userId = 100;
    int ret = 0;
    sptr<IpcRemoteBroker> listener = nullptr;
    ret = IpcServerStub::GetInstance().RegisterDeviceManagerListener(processInfo, listener);
    ASSERT_EQ(ret, ERR_DM_POINT_NULL);
}

/**
 * @tc.name: RegisterDeviceManagerListener_002
 * @tc.desc: 1. Call IpcServerStub RegisterDeviceManagerListener
 *           2. check IpcServerStub.state is ServiceRunningState::STATE_RUNNING
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, RegisterDeviceManagerListener_002, testing::ext::TestSize.Level0)
{
    std::string pkgName = "com.ohos.test";
    ProcessInfo processInfo;
    processInfo.pkgName = pkgName;
    processInfo.userId = 100;
    int ret = 0;
    sptr<IpcRemoteBroker> listener = sptr<IpcClientStub>(new IpcClientStub());
    ret = IpcServerStub::GetInstance().RegisterDeviceManagerListener(processInfo, listener);
    ASSERT_EQ(ret, DM_OK);
}

/**
 * @tc.name: RegisterDeviceManagerListener_003
 * @tc.desc: 1. Call IpcServerStub RegisterDeviceManagerListener
 *           2. check IpcServerStub.state is ServiceRunningState::STATE_RUNNING
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, RegisterDeviceManagerListener_003, testing::ext::TestSize.Level0)
{
    std::string pkgName = "";
    ProcessInfo processInfo;
    processInfo.pkgName = pkgName;
    processInfo.userId = 100;
    int ret = 0;
    sptr<IpcClientStub> listener = sptr<IpcClientStub>(new IpcClientStub());
    ret = IpcServerStub::GetInstance().RegisterDeviceManagerListener(processInfo, listener);
    ASSERT_EQ(ret, ERR_DM_POINT_NULL);
}

/**
 * @tc.name: RegisterDeviceManagerListener_004
 * @tc.desc: 1. Set PkgName is com.ohos.test
 *           2. Call IpcServerStub RegisterDeviceManagerListener with param
 *           3. check ret is DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, RegisterDeviceManagerListener_004, testing::ext::TestSize.Level0)
{
    // 1. Set PkgName is com.ohos.test
    std::string pkgName = "com.ohos.test";
    ProcessInfo processInfo;
    processInfo.pkgName = pkgName;
    processInfo.userId = 100;
    int ret = 0;
    sptr<IpcClientStub> listener = sptr<IpcClientStub>(new IpcClientStub());
    // 2. Call IpcServerStub RegisterDeviceManagerListener with param
    ret = IpcServerStub::GetInstance().RegisterDeviceManagerListener(processInfo, listener);
    // 3. check ret is DM_OK
    ASSERT_EQ(ret, DM_OK);
}

/**
 * @tc.name: RegisterDeviceManagerListener_005
 * @tc.desc: 1. Set PkgName is com.ohos.test
 *                  2. Call IpcServerStub RegisterDeviceManagerListener with param
 *                  3. check ret is DM_OK
 *                  4. Call IpcServerStub RegisterDeviceManagerListener with same pkgName another listener
 *                  5. check result is DM_OK
 *                  6. earse pkgName for appRecipient_
 *                  7. check result is DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, RegisterDeviceManagerListener_005, testing::ext::TestSize.Level0)
{
    // 1. Set PkgName is com.ohos.test
    std::string pkgName = "com.ohos.test";
    ProcessInfo processInfo;
    processInfo.pkgName = pkgName;
    processInfo.userId = 100;
    int ret = 0;
    int result = 0;
    sptr<IpcClientStub> listener = sptr<IpcClientStub>(new IpcClientStub());
    // 2. Call IpcServerStub RegisterDeviceManagerListener with param
    ret = IpcServerStub::GetInstance().RegisterDeviceManagerListener(processInfo, listener);
    // 3. check ret is DM_OK
    ASSERT_EQ(ret, DM_OK);
    sptr<IpcClientStub> listener2 = sptr<IpcClientStub>(new IpcClientStub());
    // 4. Call IpcServerStub RegisterDeviceManagerListener with same pkgName another listener
    result = IpcServerStub::GetInstance().RegisterDeviceManagerListener(processInfo, listener2);
    // 5. check result is DM_OK
    ASSERT_EQ(result, DM_OK);
    sptr<IpcClientStub> listener3 = sptr<IpcClientStub>(new IpcClientStub());
    // 6. earse pkgName for appRecipient_
    IpcServerStub::GetInstance().appRecipient_.erase(processInfo);
    result = IpcServerStub::GetInstance().RegisterDeviceManagerListener(processInfo, listener3);
    // 7. check result is DM_OK
    ASSERT_EQ(result, DM_OK);
}

/**
 * @tc.name: UnRegisterDeviceManagerListener_001
 * @tc.desc:  1. Call IpcServerStub UnRegisterDeviceManagerListener
 *            2. check ret is ERR_DM_INPUT_PARA_INVALID
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, UnRegisterDeviceManagerListener_001, testing::ext::TestSize.Level0)
{
    ProcessInfo processInfo;
    int ret = 0;
    ret = IpcServerStub::GetInstance().UnRegisterDeviceManagerListener(processInfo);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: UnRegisterDeviceManagerListener_002
 * @tc.desc:  1. Set PkgName is com.ohos.test
 *            2. Call IpcServerStub RegisterDeviceManagerListener with param
 *            3. check ret is DM_OK
 *            4. Call IpcServerStub UnRegisterDeviceManagerListener
 *            5. check ret is DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, UnRegisterDeviceManagerListener_002, testing::ext::TestSize.Level0)
{
    // 1. Set PkgName is com.ohos.test
    std::string pkgName = "com.ohos.test";
    ProcessInfo processInfo;
    processInfo.pkgName = pkgName;
    processInfo.userId = 100;
    int ret = 0;
    sptr<IpcClientStub> listener = sptr<IpcClientStub>(new IpcClientStub());
    // 2. Call IpcServerStub RegisterDeviceManagerListener with param
    ret = IpcServerStub::GetInstance().RegisterDeviceManagerListener(processInfo, listener);
    // 3. check ret is DM_OK
    ASSERT_EQ(ret, DM_OK);
    int result = 0;
    // 4. Call IpcServerStub UnRegisterDeviceManagerListener
    result = IpcServerStub::GetInstance().UnRegisterDeviceManagerListener(processInfo);
    // 5. check ret is DM_OK
    ASSERT_EQ(result, DM_OK);
}

/**
 * @tc.name: UnRegisterDeviceManagerListener_003
 * @tc.desc:  1. Set pkgName is com.ohos.test
 *            2. Call IpcServerStub UnRegisterDeviceManagerListener
 *            3. check ret is DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, UnRegisterDeviceManagerListener_003, testing::ext::TestSize.Level0)
{
    // 1. Set pkgName is com.ohos.test
    std::string pkgName = "com.ohos.test";
    ProcessInfo processInfo;
    processInfo.pkgName = pkgName;
    processInfo.userId = 100;
    int ret = 0;
    // 2. Call IpcServerStub UnRegisterDeviceManagerListener
    ret = IpcServerStub::GetInstance().UnRegisterDeviceManagerListener(processInfo);
    // 3. check ret is DM_OK
    ASSERT_EQ(ret, DM_OK);
}

/**
 * @tc.name: UnRegisterDeviceManagerListener_004
 * @tc.desc:  1. Set PkgName is com.ohos.test
 *            2. Call IpcServerStub RegisterDeviceManagerListener with param
 *            3. check ret is DM_OK
 *            4. Call IpcServerStub UnRegisterDeviceManagerListener
 *            5. check ret is DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, UnRegisterDeviceManagerListener_004, testing::ext::TestSize.Level0)
{
    // 1. Set PkgName is com.ohos.test
    std::string pkgName = "com.ohos.test1";
    ProcessInfo processInfo;
    processInfo.pkgName = pkgName;
    processInfo.userId = 100;
    int ret = 0;
    sptr<IpcClientStub> listener = sptr<IpcClientStub>(new IpcClientStub());
    // 2. Call IpcServerStub RegisterDeviceManagerListener with param
    ret = IpcServerStub::GetInstance().RegisterDeviceManagerListener(processInfo, listener);
    // 3. check ret is DM_OK
    ASSERT_EQ(ret, DM_OK);
    int result = 0;
    // 4. Call IpcServerStub UnRegisterDeviceManagerListener
    result = IpcServerStub::GetInstance().UnRegisterDeviceManagerListener(processInfo);
    // 5. check ret is DM_OK
    ASSERT_EQ(result, DM_OK);
    sptr<IpcRemoteBroker> dmListener = IpcServerStub::GetInstance().dmListener_[processInfo];
    ASSERT_EQ(dmListener, nullptr);
}

/**
 * @tc.name: UnRegisterDeviceManagerListener_005
 * @tc.desc:  1. Set PkgName is com.ohos.test
 *            2. Call IpcServerStub RegisterDeviceManagerListener with param
 *            3. check ret is DM_OK
 *            4. Call IpcServerStub UnRegisterDeviceManagerListener
 *            5. check ret is DM_OK
 *            6. Call IpcServerStub UnRegisterDeviceManagerListener
 *            7. check ret is DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, UnRegisterDeviceManagerListener_005, testing::ext::TestSize.Level0)
{
    // 1. Set PkgName is com.ohos.test
    std::string pkgName = "com.ohos.test2";
    ProcessInfo processInfo;
    processInfo.pkgName = pkgName;
    processInfo.userId = 100;
    int ret = 0;
    sptr<IpcClientStub> listener = sptr<IpcClientStub>(new IpcClientStub());
    // 2. Call IpcServerStub RegisterDeviceManagerListener with param
    ret = IpcServerStub::GetInstance().RegisterDeviceManagerListener(processInfo, listener);
    // 3. check ret is DM_OK
    ASSERT_EQ(ret, DM_OK);
    int result = 0;
    // 4. Call IpcServerStub UnRegisterDeviceManagerListener
    std::string testPkgName = "com.test";
    result = IpcServerStub::GetInstance().UnRegisterDeviceManagerListener(processInfo);
    // 5. check ret is DM_OK
    ASSERT_EQ(result, DM_OK);
    IpcServerStub::GetInstance().appRecipient_.erase(processInfo);
    // 6. Call IpcServerStub UnRegisterDeviceManagerListener
    result = IpcServerStub::GetInstance().UnRegisterDeviceManagerListener(processInfo);
    // 7. check ret is DM_OK
    ASSERT_EQ(result, DM_OK);
}

/**
 * @tc.name: GetDmListener_001
 * @tc.desc: 1. Set pkgName is com.ohos.test
 *           2. Call IpcServerStub GetDmListener
 *           3. check ret is DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, GetDmListener_001, testing::ext::TestSize.Level0)
{
    // 1. Set pkgName is com.ohos.test
    ProcessInfo processInfo;
    processInfo.pkgName = "com.ohos.test";
    sptr<IpcRemoteBroker> ret = nullptr;
    // 2. Call IpcServerStub UnRegisterDeviceManagerListener
    ret = IpcServerStub::GetInstance().GetDmListener(processInfo);
    // 3. check ret is DM_OK
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: GetDmListener_002
 * @tc.desc: 1. Set pkgName is com.ohos.test
 *           2. Call IpcServerStub GetDmListener
 *           3. check ret is DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, GetDmListener_002, testing::ext::TestSize.Level0)
{
    // 1. Set pkgName is com.ohos.test
    std::string pkgName = "com.ohos.test";
    ProcessInfo processInfo;
    processInfo.pkgName = pkgName;
    int result = 0;
    sptr<IpcClientStub> listener = sptr<IpcClientStub>(new IpcClientStub());
    // 2. Call IpcServerStub RegisterDeviceManagerListener with param
    result = IpcServerStub::GetInstance().RegisterDeviceManagerListener(processInfo, listener);
    // 3. check ret is DM_OK
    ASSERT_EQ(result, DM_OK);
    sptr<IpcRemoteBroker> ret = nullptr;
    // 2. Call IpcServerStub UnRegisterDeviceManagerListener
    ret = IpcServerStub::GetInstance().GetDmListener(processInfo);
    // 3. check ret is DM_OK
    ASSERT_NE(ret, nullptr);
}

/**
 * @tc.name: GetDmListener_003
 * @tc.desc: 1. Set pkgName is com.ohos.test
 *           2. Call IpcServerStub GetDmListener
 *           3. check ret is DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, GetDmListener_003, testing::ext::TestSize.Level0)
{
    // 1. Set pkgName is com.ohos.test
    std::string pkgName = "com.ohos.test";
    ProcessInfo processInfo;
    processInfo.pkgName = pkgName;
    int result = 0;
    sptr<IpcClientStub> listener = sptr<IpcClientStub>(new IpcClientStub());
    // 2. Call IpcServerStub RegisterDeviceManagerListener with param
    result = IpcServerStub::GetInstance().RegisterDeviceManagerListener(processInfo, listener);
    // 3. check ret is DM_OK
    ASSERT_EQ(result, DM_OK);
    sptr<IpcRemoteBroker> ret = nullptr;
    // 2. Call IpcServerStub UnRegisterDeviceManagerListener
    ret = IpcServerStub::GetInstance().GetDmListener(processInfo);
    // 3. check ret is DM_OK
    ASSERT_NE(ret, nullptr);
}

/**
 * @tc.name: GetDmListener_004
 * @tc.desc: 1. Set pkgName is com.ohos.test
 *           2. Call IpcServerStub GetDmListener
 *           3. check ret is ERR_DM_POINT_NULL
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, GetDmListener_004, testing::ext::TestSize.Level0)
{
    // 1. Set pkgName is null
    std::string pkgName = "";
    ProcessInfo processInfo;
    processInfo.pkgName = pkgName;
    int result = 0;
    sptr<IpcClientStub> listener = sptr<IpcClientStub>(new IpcClientStub());
    // 2. Call IpcServerStub RegisterDeviceManagerListener with param
    result = IpcServerStub::GetInstance().RegisterDeviceManagerListener(processInfo, listener);
    // 3. check ret is ERR_DM_POINT_NULL
    ASSERT_EQ(result, ERR_DM_POINT_NULL);
    sptr<IpcRemoteBroker> ret = nullptr;
    // 2. Call IpcServerStub UnRegisterDeviceManagerListener
    ret = IpcServerStub::GetInstance().GetDmListener(processInfo);
    // 3. check ret is nullptr
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: GetDmListener_005
 * @tc.desc: 1. Set pkgName is com.ohos.test
 *           2. Call IpcServerStub GetDmListener
 *           3. check ret is ERR_DM_POINT_NULL
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, GetDmListener_005, testing::ext::TestSize.Level0)
{
    // 1. Set pkgName is null
    std::string pkgName = "com.test.ohos";
    ProcessInfo processInfo;
    processInfo.pkgName = pkgName;
    int result = 0;
    sptr<IpcClientStub> listener = nullptr;
    // 2. Call IpcServerStub RegisterDeviceManagerListener with param
    result = IpcServerStub::GetInstance().RegisterDeviceManagerListener(processInfo, listener);
    // 3. check ret is ERR_DM_POINT_NULL
    ASSERT_EQ(result, ERR_DM_POINT_NULL);
    sptr<IpcRemoteBroker> ret = nullptr;
    // 2. Call IpcServerStub UnRegisterDeviceManagerListener
    ret = IpcServerStub::GetInstance().GetDmListener(processInfo);
    // 3. check ret is nullptr
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: OnRemoveSystemAbility_001
 * @tc.type: FUNC
 */
HWTEST_F(IpcServerStubTest, OnRemoveSystemAbility_001, testing::ext::TestSize.Level0)
{
    int32_t systemAbilityId = SOFTBUS_SERVER_SA_ID;
    std::string deviceId;
    IpcServerStub::GetInstance().OnRemoveSystemAbility(systemAbilityId, deviceId);
    ASSERT_EQ(DeviceManagerService::GetInstance().softbusListener_, nullptr);
}

/**
 * @tc.name: OnRemoveSystemAbility_002
 * @tc.type: FUNC
 */
HWTEST_F(IpcServerStubTest, OnRemoveSystemAbility_002, testing::ext::TestSize.Level0)
{
    int32_t systemAbilityId = DISTRIBUTED_HARDWARE_SA_ID;
    std::string deviceId;
    IpcServerStub::GetInstance().OnRemoveSystemAbility(systemAbilityId, deviceId);
    ASSERT_EQ(DeviceManagerService::GetInstance().softbusListener_, nullptr);
}

/**
 * @tc.name: OnAddSystemAbility_001
 * @tc.type: FUNC
 */
HWTEST_F(IpcServerStubTest, OnAddSystemAbility_001, testing::ext::TestSize.Level0)
{
    int32_t systemAbilityId = SOFTBUS_SERVER_SA_ID;
    std::string deviceId;
    IpcServerStub::GetInstance().OnAddSystemAbility(systemAbilityId, deviceId);
    ASSERT_NE(DeviceManagerService::GetInstance().softbusListener_, nullptr);
    IpcServerStub::GetInstance().OnRemoveSystemAbility(systemAbilityId, deviceId);
}

/**
 * @tc.name: OnAddSystemAbility_002
 * @tc.type: FUNC
 */
HWTEST_F(IpcServerStubTest, OnAddSystemAbility_002, testing::ext::TestSize.Level0)
{
    int32_t systemAbilityId = 9999;
    std::string deviceId;
    IpcServerStub::GetInstance().OnAddSystemAbility(systemAbilityId, deviceId);

    systemAbilityId = SOFTBUS_SERVER_SA_ID;
    IpcServerStub::GetInstance().registerToService_ = false;
    IpcServerStub::GetInstance().OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_NE(DeviceManagerService::GetInstance().softbusListener_, nullptr);

    DeviceManagerService::GetInstance().softbusListener_ = nullptr;
    systemAbilityId = SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN;
    IpcServerStub::GetInstance().OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_EQ(DeviceManagerService::GetInstance().softbusListener_, nullptr);

    systemAbilityId = SCREENLOCK_SERVICE_ID;
    IpcServerStub::GetInstance().OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_EQ(DeviceManagerService::GetInstance().softbusListener_, nullptr);
}

/**
 * @tc.name: GetAllProcessInfo_001
 * @tc.type: FUNC
 */
HWTEST_F(IpcServerStubTest, GetAllProcessInfo_001, testing::ext::TestSize.Level0)
{
    std::vector<ProcessInfo>  processInfo;
    processInfo = IpcServerStub::GetInstance().GetAllProcessInfo();
    ASSERT_EQ(processInfo.empty(), false);
}

/**
 * @tc.name: Dump_001
 * @tc.type: FUNC
 */
HWTEST_F(IpcServerStubTest, Dump_001, testing::ext::TestSize.Level0)
{
    int32_t fd = 0;
    std::vector<std::u16string> args;
    int32_t ret = IpcServerStub::GetInstance().Dump(fd, args);
    ASSERT_NE(ret, DM_OK);
}

HWTEST_F(IpcServerStubTest, HandleSoftBusServerAdd_001, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().registerToService_ = true;
    IpcServerStub::GetInstance().state_ = ServiceRunningState::STATE_NOT_START;
    IpcServerStub::GetInstance().HandleSoftBusServerAdd();

    EXPECT_EQ(ServiceRunningState::STATE_RUNNING, IpcServerStub::GetInstance().state_);
    EXPECT_NE(DeviceManagerService::GetInstance().softbusListener_, nullptr);
}

HWTEST_F(IpcServerStubTest, HandleSoftBusServerAdd_002, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().registerToService_ = false;
    IpcServerStub::GetInstance().state_ = ServiceRunningState::STATE_NOT_START;
    IpcServerStub::GetInstance().HandleSoftBusServerAdd();

    EXPECT_EQ(ServiceRunningState::STATE_NOT_START, IpcServerStub::GetInstance().state_);
    EXPECT_NE(DeviceManagerService::GetInstance().softbusListener_, nullptr);
}

HWTEST_F(IpcServerStubTest, AddDelimiter_001, testing::ext::TestSize.Level0)
{
    std::string input = "";
    std::string result = IpcServerStub::GetInstance().AddDelimiter(input);
    ASSERT_EQ(result, "");
}

HWTEST_F(IpcServerStubTest, AddDelimiter_002, testing::ext::TestSize.Level0)
{
    std::string input = "path/";
    std::string result = IpcServerStub::GetInstance().AddDelimiter(input);
    ASSERT_EQ(result, "path/");
}

HWTEST_F(IpcServerStubTest, AddDelimiter_003, testing::ext::TestSize.Level0)
{
    std::string input = "path";
    std::string result = IpcServerStub::GetInstance().AddDelimiter(input);
    ASSERT_EQ(result, "path/");
}

HWTEST_F(IpcServerStubTest, JoinPath_001, testing::ext::TestSize.Level0)
{
    std::string prefixPath = "path";
    std::string subPath = "subpath";
    std::string result = IpcServerStub::GetInstance().JoinPath(prefixPath, subPath);
    ASSERT_EQ(result, "path/subpath");
}

HWTEST_F(IpcServerStubTest, JoinPath_002, testing::ext::TestSize.Level0)
{
    std::string prefixPath = "path/";
    std::string subPath = "subpath";
    std::string result = IpcServerStub::GetInstance().JoinPath(prefixPath, subPath);
    ASSERT_EQ(result, "path/subpath");
}

HWTEST_F(IpcServerStubTest, JoinPath_003, testing::ext::TestSize.Level0)
{
    std::string prefixPath = "";
    std::string subPath = "subpath";
    std::string result = IpcServerStub::GetInstance().JoinPath(prefixPath, subPath);
    ASSERT_EQ(result, "subpath");
}

HWTEST_F(IpcServerStubTest, JoinPath_004, testing::ext::TestSize.Level0)
{
    std::string prefixPath = "path";
    std::string subPath = "";
    std::string result = IpcServerStub::GetInstance().JoinPath(prefixPath, subPath);
    ASSERT_EQ(result, "path/");
}

HWTEST_F(IpcServerStubTest, JoinPath_005, testing::ext::TestSize.Level0)
{
    std::string prefixPath = "";
    std::string subPath = "";
    std::string result = IpcServerStub::GetInstance().JoinPath(prefixPath, subPath);
    ASSERT_EQ(result, "");
}

HWTEST_F(IpcServerStubTest, JoinPath_006, testing::ext::TestSize.Level0)
{
    std::string prefixPath = "path";
    std::string subPath = "/subpath";
    std::string result = IpcServerStub::GetInstance().JoinPath(prefixPath, subPath);
    ASSERT_EQ(result, "path//subpath");
}

HWTEST_F(IpcServerStubTest, JoinPath_007, testing::ext::TestSize.Level0)
{
    std::string prefixPath = "path/";
    std::string subPath = "/subpath";
    std::string result = IpcServerStub::GetInstance().JoinPath(prefixPath, subPath);
    ASSERT_EQ(result, "path//subpath");
}

HWTEST_F(IpcServerStubTest, JoinPath2_001, testing::ext::TestSize.Level0)
{
    std::string prefixPath = "path";
    std::string midPath = "midpath";
    std::string subPath = "subpath";
    std::string result = IpcServerStub::GetInstance().JoinPath(prefixPath, midPath, subPath);
    ASSERT_EQ(result, "path/midpath/subpath");
}

HWTEST_F(IpcServerStubTest, JoinPath2_002, testing::ext::TestSize.Level0)
{
    std::string prefixPath = "path";
    std::string midPath = "";
    std::string subPath = "subpath";
    std::string result = IpcServerStub::GetInstance().JoinPath(prefixPath, midPath, subPath);
    ASSERT_EQ(result, "path/subpath");
}

HWTEST_F(IpcServerStubTest, JoinPath2_003, testing::ext::TestSize.Level0)
{
    std::string prefixPath = "path";
    std::string midPath = "midpath";
    std::string subPath = "";
    std::string result = IpcServerStub::GetInstance().JoinPath(prefixPath, midPath, subPath);
    ASSERT_EQ(result, "path/midpath/");
}

HWTEST_F(IpcServerStubTest, JoinPath2_004, testing::ext::TestSize.Level0)
{
    std::string prefixPath = "";
    std::string midPath = "midpath";
    std::string subPath = "";
    std::string result = IpcServerStub::GetInstance().JoinPath(prefixPath, midPath, subPath);
    ASSERT_EQ(result, "midpath/");
}

HWTEST_F(IpcServerStubTest, JoinPath2_005, testing::ext::TestSize.Level0)
{
    std::string prefixPath = "";
    std::string midPath = "";
    std::string subPath = "";
    std::string result = IpcServerStub::GetInstance().JoinPath(prefixPath, midPath, subPath);
    ASSERT_EQ(result, "");
}

HWTEST_F(IpcServerStubTest, JoinPath2_006, testing::ext::TestSize.Level0)
{
    std::string prefixPath = "path/";
    std::string midPath = "/midpath/";
    std::string subPath = "/subpath";
    std::string result = IpcServerStub::GetInstance().JoinPath(prefixPath, midPath, subPath);
    ASSERT_EQ(result, "path//midpath//subpath");
}

/**
 * @tc.name: SetCriticalState_001
 * @tc.desc: 1. set isCritical_ to false
 *           2. call SetCriticalState(false) (same state)
 *           3. verify isCritical_ remains false (early return, no SetCritical call)
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, SetCriticalState_001, testing::ext::TestSize.Level0)
{
    // 1. set isCritical_ to false
    IpcServerStub::GetInstance().isCritical_ = false;
    // 2. call SetCriticalState(false) (same state -> early return)
    IpcServerStub::GetInstance().SetCriticalState(false);
    // 3. verify isCritical_ remains false
    ASSERT_EQ(IpcServerStub::GetInstance().isCritical_.load(), false);
}

/**
 * @tc.name: RunningIpcCount_001
 * @tc.desc: 1. reset runningIpcCount_ to 0
 *           2. call AddRunningIpcCount, verify count is 1
 *           3. call SubtractRunningIpcCount, verify count returns to 0
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, RunningIpcCount_001, testing::ext::TestSize.Level0)
{
    // 1. reset runningIpcCount_ to 0
    IpcServerStub::GetInstance().runningIpcCount_ = 0;
    IpcServerStub::GetInstance().isCritical_ = false;
    // 2. call AddRunningIpcCount, verify count is 1
    IpcServerStub::GetInstance().AddRunningIpcCount();
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 1);
    // 3. call SubtractRunningIpcCount, verify count returns to 0
    IpcServerStub::GetInstance().SubtractRunningIpcCount();
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 0);
    // cleanup the idle critical timer started by 1->0 transition
    IpcServerStub::GetInstance().CancelIdleCriticalTask();
}

/**
 * @tc.name: OnRemoteRequest_003
 * @tc.desc: 1. call OnRemoteRequest with a CLIENT_CODE_3RD code
 *           2. verify runningIpcCount_ is balanced (returns to 0)
 *           3. verify ret is not DM_OK (3rd so load fails)
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, OnRemoteRequest_003, testing::ext::TestSize.Level0)
{
    // 1. reset count and call OnRemoteRequest with a 3rd code
    IpcServerStub::GetInstance().runningIpcCount_ = 0;
    IpcServerStub::GetInstance().isCritical_ = false;
    // 1000 is INIT_DEVICE_MANAGER (a CLIENT_CODE_3RD entry)
    constexpr uint32_t code3rd = 1000;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    // 2. call OnRemoteRequest
    int32_t ret = IpcServerStub::GetInstance().OnRemoteRequest(code3rd, data, reply, option);
    // 3. verify count is balanced and ret is not DM_OK
    ASSERT_NE(ret, DM_OK);
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 0);
    IpcServerStub::GetInstance().CancelIdleCriticalTask();
}

/**
 * @tc.name: OnRemoteRequest_004
 * @tc.desc: 1. call OnRemoteRequest with an unsupported code (not in CLIENT_CODE/CLIENT_CODE_3RD)
 *           2. verify runningIpcCount_ is balanced (returns to 0)
 *           3. verify ret is not DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, OnRemoteRequest_004, testing::ext::TestSize.Level0)
{
    // 1. reset count and call OnRemoteRequest with an unsupported code
    IpcServerStub::GetInstance().runningIpcCount_ = 0;
    IpcServerStub::GetInstance().isCritical_ = false;
    constexpr uint32_t unsupportedCode = 9999;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    // 2. call OnRemoteRequest
    int32_t ret = IpcServerStub::GetInstance().OnRemoteRequest(unsupportedCode, data, reply, option);
    // 3. verify count is balanced and ret is not DM_OK
    ASSERT_NE(ret, DM_OK);
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 0);
    IpcServerStub::GetInstance().CancelIdleCriticalTask();
}

/**
 * @tc.name: OnRemoteRequest_005
 * @tc.desc: 1. write a valid interface token to the data parcel
 *           2. call OnRemoteRequest with a code that passes token check but is
 *              not registered in IpcCmdRegister (>= IPC_MSG_BUTT)
 *           3. verify the unsupported-code branch is taken (IPCObjectStub fallback)
 *              and runningIpcCount_ is balanced
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, OnRemoteRequest_005, testing::ext::TestSize.Level0)
{
    // 1. reset count and write a valid interface token
    IpcServerStub::GetInstance().runningIpcCount_ = 0;
    IpcServerStub::GetInstance().isCritical_ = false;
    // use a code >= IPC_MSG_BUTT so OnIpcCmd returns ERR_DM_UNSUPPORTED_IPC_COMMAND
    constexpr uint32_t unregisteredCode = 500;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IpcServerStub::GetInstance().GetDescriptor());
    // 2. call OnRemoteRequest
    int32_t ret = IpcServerStub::GetInstance().OnRemoteRequest(unregisteredCode, data, reply, option);
    // 3. verify count is balanced and ret is not DM_OK (unsupported code fallback)
    ASSERT_NE(ret, DM_OK);
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 0);
    IpcServerStub::GetInstance().CancelIdleCriticalTask();
}

/**
 * @tc.name: RunningIpcCount_002
 * @tc.desc: 1. reset runningIpcCount_ to 0
 *           2. call AddRunningIpcCount three times (0->1->2->3)
 *           3. call SubtractRunningIpcCount three times (3->2->1->0)
 *           4. verify count returns to 0
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, RunningIpcCount_002, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().runningIpcCount_ = 0;
    IpcServerStub::GetInstance().isCritical_ = false;
    IpcServerStub::GetInstance().AddRunningIpcCount();
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 1);
    IpcServerStub::GetInstance().AddRunningIpcCount();
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 2);
    IpcServerStub::GetInstance().AddRunningIpcCount();
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 3);
    IpcServerStub::GetInstance().SubtractRunningIpcCount();
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 2);
    IpcServerStub::GetInstance().SubtractRunningIpcCount();
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 1);
    IpcServerStub::GetInstance().SubtractRunningIpcCount();
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 0);
    IpcServerStub::GetInstance().CancelIdleCriticalTask();
}

/**
 * @tc.name: RunningIpcCount_003
 * @tc.desc: 1. set runningIpcCount_ to 2 and isCritical_ to true
 *           2. call AddRunningIpcCount (2->3, no critical state change)
 *           3. call SubtractRunningIpcCount (3->2, no timer start since count > 0)
 *           4. verify isCritical_ remains true
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, RunningIpcCount_003, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().runningIpcCount_ = 2;
    IpcServerStub::GetInstance().isCritical_ = true;
    IpcServerStub::GetInstance().AddRunningIpcCount();
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 3);
    ASSERT_EQ(IpcServerStub::GetInstance().isCritical_.load(), true);
    IpcServerStub::GetInstance().SubtractRunningIpcCount();
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 2);
    ASSERT_EQ(IpcServerStub::GetInstance().isCritical_.load(), true);
    IpcServerStub::GetInstance().runningIpcCount_ = 0;
    IpcServerStub::GetInstance().CancelIdleCriticalTask();
}

/**
 * @tc.name: StartIdleCriticalTask_001
 * @tc.desc: 1. call StartIdleCriticalTask directly
 *           2. call CancelIdleCriticalTask to clean up
 *           3. verify no crash
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, StartIdleCriticalTask_001, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().runningIpcCount_ = 0;
    IpcServerStub::GetInstance().isCritical_ = true;
    IpcServerStub::GetInstance().StartIdleCriticalTask();
    IpcServerStub::GetInstance().CancelIdleCriticalTask();
    ASSERT_EQ(IpcServerStub::GetInstance().isCritical_.load(), true);
}

/**
 * @tc.name: CancelIdleCriticalTask_001
 * @tc.desc: 1. call CancelIdleCriticalTask without prior StartIdleCriticalTask
 *           2. verify no crash
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, CancelIdleCriticalTask_001, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().CancelIdleCriticalTask();
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 0);
}

/**
 * @tc.name: SetCriticalState_004
 * @tc.desc: 1. set isCritical_ to true
 *           2. call SetCriticalState(true) (same state)
 *           3. verify isCritical_ remains true (early return)
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, SetCriticalState_004, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().isCritical_ = true;
    IpcServerStub::GetInstance().SetCriticalState(true);
    ASSERT_EQ(IpcServerStub::GetInstance().isCritical_.load(), true);
}

/**
 * @tc.name: OnRemoteRequest_006
 * @tc.desc: 1. call OnRemoteRequest with SERVER_DEVICE_STATE_NOTIFY (a CLIENT_CODE entry)
 *           2. verify runningIpcCount_ is balanced (returns to 0)
 *           3. verify ret is not DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, OnRemoteRequest_006, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().runningIpcCount_ = 0;
    IpcServerStub::GetInstance().isCritical_ = false;
    uint32_t code = SERVER_DEVICE_STATE_NOTIFY;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = IpcServerStub::GetInstance().OnRemoteRequest(code, data, reply, option);
    ASSERT_NE(ret, DM_OK);
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 0);
    IpcServerStub::GetInstance().CancelIdleCriticalTask();
}

/**
 * @tc.name: RunningIpcCount_004
 * @tc.desc: 1. reset runningIpcCount_ to 0 and isCritical_ to false
 *           2. call AddRunningIpcCount (0->1, SetCriticalState(true))
 *           3. call AddRunningIpcCount (1->2, no state change)
 *           4. call SubtractRunningIpcCount (2->1, no timer start)
 *           5. call SubtractRunningIpcCount (1->0, StartIdleCriticalTask)
 *           6. call CancelIdleCriticalTask to clean up
 *           7. verify isCritical_ is true (timer not fired, state not changed back)
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, RunningIpcCount_004, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().runningIpcCount_ = 0;
    IpcServerStub::GetInstance().isCritical_ = false;
    IpcServerStub::GetInstance().AddRunningIpcCount();
    ASSERT_EQ(IpcServerStub::GetInstance().isCritical_.load(), false);
    IpcServerStub::GetInstance().AddRunningIpcCount();
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 2);
    IpcServerStub::GetInstance().SubtractRunningIpcCount();
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 1);
    IpcServerStub::GetInstance().SubtractRunningIpcCount();
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 0);
    IpcServerStub::GetInstance().CancelIdleCriticalTask();
    ASSERT_EQ(IpcServerStub::GetInstance().isCritical_.load(), false);
}

/**
 * @tc.name: StartIdleCriticalTask_002
 * @tc.desc: 1. call StartIdleCriticalTask twice (second call should delete first timer)
 *           2. call CancelIdleCriticalTask to clean up
 *           3. verify no crash
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, StartIdleCriticalTask_002, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().runningIpcCount_ = 0;
    IpcServerStub::GetInstance().isCritical_ = true;
    IpcServerStub::GetInstance().StartIdleCriticalTask();
    IpcServerStub::GetInstance().StartIdleCriticalTask();
    IpcServerStub::GetInstance().CancelIdleCriticalTask();
    ASSERT_EQ(IpcServerStub::GetInstance().isCritical_.load(), true);
}

/**
 * @tc.name: CancelIdleCriticalTask_002
 * @tc.desc: 1. call StartIdleCriticalTask then CancelIdleCriticalTask
 *           2. call CancelIdleCriticalTask again (no active timer)
 *           3. verify no crash
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, CancelIdleCriticalTask_002, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().runningIpcCount_ = 0;
    IpcServerStub::GetInstance().isCritical_ = true;
    IpcServerStub::GetInstance().StartIdleCriticalTask();
    IpcServerStub::GetInstance().CancelIdleCriticalTask();
    IpcServerStub::GetInstance().CancelIdleCriticalTask();
    ASSERT_EQ(IpcServerStub::GetInstance().isCritical_.load(), true);
}

/**
 * @tc.name: OnRemoteRequest_007
 * @tc.desc: 1. call OnRemoteRequest with SERVER_DEVICE_FOUND (a CLIENT_CODE entry)
 *           2. verify runningIpcCount_ is balanced (returns to 0)
 *           3. verify ret is not DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, OnRemoteRequest_007, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().runningIpcCount_ = 0;
    IpcServerStub::GetInstance().isCritical_ = false;
    uint32_t code = SERVER_DEVICE_FOUND;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = IpcServerStub::GetInstance().OnRemoteRequest(code, data, reply, option);
    ASSERT_NE(ret, DM_OK);
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 0);
    IpcServerStub::GetInstance().CancelIdleCriticalTask();
}

/**
 * @tc.name: OnRemoteRequest_008
 * @tc.desc: 1. call OnRemoteRequest with SERVER_AUTH_RESULT (a CLIENT_CODE entry)
 *           2. verify runningIpcCount_ is balanced (returns to 0)
 *           3. verify ret is not DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, OnRemoteRequest_008, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().runningIpcCount_ = 0;
    IpcServerStub::GetInstance().isCritical_ = false;
    uint32_t code = SERVER_AUTH_RESULT;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = IpcServerStub::GetInstance().OnRemoteRequest(code, data, reply, option);
    ASSERT_NE(ret, DM_OK);
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 0);
    IpcServerStub::GetInstance().CancelIdleCriticalTask();
}

/**
 * @tc.name: OnRemoteRequest_009
 * @tc.desc: 1. call OnRemoteRequest with SERVER_PUBLISH_FINISH (a CLIENT_CODE entry)
 *           2. verify runningIpcCount_ is balanced (returns to 0)
 *           3. verify ret is not DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, OnRemoteRequest_009, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().runningIpcCount_ = 0;
    IpcServerStub::GetInstance().isCritical_ = false;
    uint32_t code = SERVER_PUBLISH_FINISH;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = IpcServerStub::GetInstance().OnRemoteRequest(code, data, reply, option);
    ASSERT_NE(ret, DM_OK);
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 0);
    IpcServerStub::GetInstance().CancelIdleCriticalTask();
}

/**
 * @tc.name: OnRemoteRequest_010
 * @tc.desc: 1. call OnRemoteRequest with UNBIND_TARGET_RESULT (a CLIENT_CODE entry)
 *           2. verify runningIpcCount_ is balanced (returns to 0)
 *           3. verify ret is not DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, OnRemoteRequest_010, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().runningIpcCount_ = 0;
    IpcServerStub::GetInstance().isCritical_ = false;
    uint32_t code = UNBIND_TARGET_RESULT;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = IpcServerStub::GetInstance().OnRemoteRequest(code, data, reply, option);
    ASSERT_NE(ret, DM_OK);
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 0);
    IpcServerStub::GetInstance().CancelIdleCriticalTask();
}

/**
 * @tc.name: OnRemoteRequest_011
 * @tc.desc: 1. call OnRemoteRequest with IMPORT_PINCODE_3RD (a CLIENT_CODE_3RD entry)
 *           2. verify runningIpcCount_ is balanced (returns to 0)
 *           3. verify ret is not DM_OK (3rd so load fails)
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(IpcServerStubTest, OnRemoteRequest_011, testing::ext::TestSize.Level0)
{
    IpcServerStub::GetInstance().runningIpcCount_ = 0;
    IpcServerStub::GetInstance().isCritical_ = false;
    // 1003 is IMPORT_PINCODE_3RD (a CLIENT_CODE_3RD entry)
    constexpr uint32_t code3rd = 1003;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = IpcServerStub::GetInstance().OnRemoteRequest(code3rd, data, reply, option);
    ASSERT_NE(ret, DM_OK);
    ASSERT_EQ(IpcServerStub::GetInstance().runningIpcCount_.load(), 0);
    IpcServerStub::GetInstance().CancelIdleCriticalTask();
}
} // namespace
} // namespace DistributedHardware
} // namespace OHOS
