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

#include "UTTest_device_manager_service_three.h"

#include "accesstoken_kit.h"
#include "dm_constants.h"
#include "dm_device_info.h"
#include "dm_log.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

using namespace OHOS::Security::AccessToken;
using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace DistributedHardware {

void DeviceManagerServiceThreeTest::SetUp()
{
    const int32_t permsNum = 4;
    const int32_t indexZero = 0;
    const int32_t indexOne = 1;
    const int32_t indexTwo = 2;
    const int32_t indexThree = 3;
    uint64_t tokenId;
    const char *perms[permsNum];
    perms[indexZero] = "ohos.permission.DISTRIBUTED_SOFTBUS_CENTER";
    perms[indexOne] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[indexTwo] = "ohos.permission.ACCESS_SERVICE_DM";
    perms[indexThree] = "ohos.permission.MONITOR_DEVICE_NETWORK_STATE";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permsNum,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "dsoftbus_service",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

void DeviceManagerServiceThreeTest::TearDown()
{
}

void DeviceManagerServiceThreeTest::SetUpTestCase()
{
    DmDeviceManagerService::dmDeviceManagerService = deviceManagerServiceMock_;
    DmPermissionManager::dmPermissionManager = permissionManagerMock_;
    DmSoftbusListener::dmSoftbusListener = softbusListenerMock_;
    DmDeviceManagerServiceImpl::dmDeviceManagerServiceImpl = deviceManagerServiceImplMock_;
}

void DeviceManagerServiceThreeTest::TearDownTestCase()
{
    deviceManagerServiceMock_ = nullptr;
    permissionManagerMock_ = nullptr;
    softbusListenerMock_ = nullptr;
    deviceManagerServiceImplMock_ = nullptr;
}

namespace {

/**
 * @tc.name: AuthenticateDevice_301
 * @tc.desc: Set unsupport authType = 0 and return ERR_DM_NOT_INIT
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerServiceThreeTest, AuthenticateDevice_301, testing::ext::TestSize.Level0)
{
    std::string pkgName = "com.ohos.test";
    std::string extra = "jdddd";
    int32_t authType = 1;
    std::string deviceId = "deviceId";
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().AuthenticateDevice(pkgName, authType, deviceId, extra);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

/**
 * @tc.name: UnAuthenticateDevice_301
 * @tc.desc: Set intFlag for UnAuthenticateDevice to true and pkgName to com.ohos.test; set deviceId null ，The return
 * value is SOFTBUS_IPC_ERR
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerServiceThreeTest, UnAuthenticateDevice_301, testing::ext::TestSize.Level0)
{
    std::string pkgName = "com.ohos.test";
    std::string networkId = "12345";
    EXPECT_CALL(*softbusListenerMock_, GetUdidByNetworkId(_, _)).WillOnce(Return(DM_OK));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int ret = DeviceManagerService::GetInstance().UnAuthenticateDevice(pkgName, networkId);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

/**
 * @tc.name: SetUserOperation_301
 * @tc.desc: Make pkgName empty for SetUserOperation，The return value is
 * DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerServiceThreeTest, SetUserOperation_301, testing::ext::TestSize.Level0)
{
    std::string pkgName = "pkgName";
    int32_t action = 0;
    const std::string param = "extra";
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int ret = DeviceManagerService::GetInstance().SetUserOperation(pkgName, action, param);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

/**
 * @tc.name: RequestCredential_301
 * @tc.desc:The return value is ERR_DM_FAILED
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerServiceThreeTest, RequestCredential_301, testing::ext::TestSize.Level0)
{
    const std::string reqJsonStr = "test";
    std::string returnJsonStr = "returntest";
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().RequestCredential(reqJsonStr, returnJsonStr);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

/**
 * @tc.name: ImportCredential_301
 * @tc.desc:The return value is ERR_DM_NOT_INIT
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerServiceThreeTest, ImportCredential_301, testing::ext::TestSize.Level0)
{
    const std::string pkgName = "pkgNametest";
    const std::string credentialInfo = "credentialInfotest";
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().ImportCredential(pkgName, credentialInfo);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

/**
 * @tc.name: DeleteCredential_301
 * @tc.desc:The return value is ERR_DM_FAILED
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerServiceThreeTest, DeleteCredential_301, testing::ext::TestSize.Level0)
{
    const std::string pkgName = "pkgNametest";
    const std::string deleteInfo = "deleteInfotest";
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().DeleteCredential(pkgName, deleteInfo);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

/**
 * @tc.name: RegisterCredentialCallback_301
 * @tc.desc: The return value is DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerServiceThreeTest, RegisterCredentialCallback_301, testing::ext::TestSize.Level0)
{
    const std::string pkgName = "pkgNametest";
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().RegisterCredentialCallback(pkgName);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, BindDevice_301, testing::ext::TestSize.Level0)
{
    std::string pkgName = "com.ohos.test";
    int32_t authType = 1;
    std::string deviceId = "1234";
    std::string bindParam;
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().BindDevice(pkgName, authType, deviceId, bindParam);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, UnBindDevice_301, testing::ext::TestSize.Level0)
{
    std::string pkgName = "com.ohos.test";
    std::string deviceId = "1234";
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().UnBindDevice(pkgName, deviceId);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, MineRequestCredential_301, testing::ext::TestSize.Level0)
{
    DeviceManagerService::GetInstance().isImplsoLoaded_ = false;
    std::string pkgName;
    std::string returnJsonStr;
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().MineRequestCredential(pkgName, returnJsonStr);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, CheckCredential_301, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    std::string returnJsonStr;
    std::string reqJsonStr;
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().CheckCredential(pkgName, reqJsonStr, returnJsonStr);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, RegisterUiStateCallback_301, testing::ext::TestSize.Level0)
{
    std::string pkgName = "pkgName";
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().RegisterUiStateCallback(pkgName);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, UnRegisterUiStateCallback_301, testing::ext::TestSize.Level0)
{
    std::string pkgName = "pkgName";
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().UnRegisterUiStateCallback(pkgName);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, NotifyEvent_301, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    int32_t eventId = 0;
    std::string event;
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().NotifyEvent(pkgName, eventId, event);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, BindTarget_301, testing::ext::TestSize.Level0)
{
    std::string pkgName = "pkgName";
    PeerTargetId targetId;
    std::map<std::string, std::string> bindParam;
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().BindTarget(pkgName, targetId, bindParam);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, DpAclAdd_301, testing::ext::TestSize.Level0)
{
    std::string udid = "udid";
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().DpAclAdd(udid);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, IsSameAccount_301, testing::ext::TestSize.Level0)
{
    std::string udid = "udidTest";
    EXPECT_CALL(*softbusListenerMock_, GetUdidByNetworkId(_, _)).WillOnce(Return(DM_OK));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().IsSameAccount(udid);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, CheckIsSameAccount_301, testing::ext::TestSize.Level0)
{
    DmAccessCaller caller;
    DmAccessCallee callee;
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    bool ret = DeviceManagerService::GetInstance().CheckIsSameAccount(caller, callee);
    EXPECT_FALSE(ret);
}

HWTEST_F(DeviceManagerServiceThreeTest, CheckAccessControl_301, testing::ext::TestSize.Level0)
{
    DmAccessCaller caller;
    DmAccessCallee callee;
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    bool ret = DeviceManagerService::GetInstance().CheckAccessControl(caller, callee);
    EXPECT_FALSE(ret);
}

HWTEST_F(DeviceManagerServiceThreeTest, StopAuthenticateDevice_301, testing::ext::TestSize.Level0)
{
    std::string pkgName = "pkgName_003";
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().StopAuthenticateDevice(pkgName);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, ImportAuthCode_301, testing::ext::TestSize.Level0)
{
    std::string pkgName = "pkgName";
    std::string authCode = "authCode";
    EXPECT_CALL(*permissionManagerMock_, CheckProcessNameValidOnAuthCode(_)).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().ImportAuthCode(pkgName, authCode);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, ExportAuthCode_301, testing::ext::TestSize.Level0)
{
    std::string authCode = "authCode";
    EXPECT_CALL(*permissionManagerMock_, CheckProcessNameValidOnAuthCode(_)).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().ExportAuthCode(authCode);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}
} // namespace
} // namespace DistributedHardware
} // namespace OHOS