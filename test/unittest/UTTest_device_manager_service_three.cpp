/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
    Mock::VerifyAndClearExpectations(deviceManagerServiceMock_.get());
    Mock::VerifyAndClearExpectations(permissionManagerMock_.get());
    Mock::VerifyAndClearExpectations(softbusListenerMock_.get());
    Mock::VerifyAndClearExpectations(deviceManagerServiceImplMock_.get());
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
    DmDeviceManagerService::dmDeviceManagerService = nullptr;
    deviceManagerServiceMock_ = nullptr;
    DmPermissionManager::dmPermissionManager = nullptr;
    permissionManagerMock_ = nullptr;
    DmSoftbusListener::dmSoftbusListener = nullptr;
    softbusListenerMock_ = nullptr;
    DmDeviceManagerServiceImpl::dmDeviceManagerServiceImpl = nullptr;
    deviceManagerServiceImplMock_ = nullptr;
}

namespace {

const int32_t SEND_DELAY_MAX_TIME = 5;

void SetSetDnPolicyPermission()
{
    const int32_t permsNum = 1;
    const int32_t indexZero = 0;
    uint64_t tokenId;
    const char *perms[permsNum];
    perms[indexZero] = "ohos.permission.ACCESS_SERVICE_DM";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permsNum,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "collaboration_service",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/**
 * @tc.name: AuthenticateDevice_301
 * @tc.desc: Set unsupport authType = 0 and return ERR_DM_NOT_INIT
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerServiceThreeTest, AuthenticateDevice_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "com.ohos.test";
    std::string extra = "jdddd";
    int32_t authType = 1;
    std::string deviceId = "deviceId";
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
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
HWTEST_F(DeviceManagerServiceThreeTest, UnAuthenticateDevice_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "com.ohos.test";
    std::string networkId = "12345";
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
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
HWTEST_F(DeviceManagerServiceThreeTest, SetUserOperation_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "pkgName";
    int32_t action = 0;
    const std::string param = "extra";
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
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
HWTEST_F(DeviceManagerServiceThreeTest, RequestCredential_301, testing::ext::TestSize.Level1)
{
    const std::string reqJsonStr = "test";
    std::string returnJsonStr = "returntest";
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
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
HWTEST_F(DeviceManagerServiceThreeTest, ImportCredential_301, testing::ext::TestSize.Level1)
{
    const std::string pkgName = "pkgNametest";
    const std::string credentialInfo = "credentialInfotest";
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().ImportCredential(pkgName, credentialInfo);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);

    std::string reqJsonStr = "";
    std::string returnJsonStr = "";
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    ret = DeviceManagerService::GetInstance().ImportCredential(pkgName, reqJsonStr, returnJsonStr);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

/**
 * @tc.name: DeleteCredential_301
 * @tc.desc:The return value is ERR_DM_FAILED
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerServiceThreeTest, DeleteCredential_301, testing::ext::TestSize.Level1)
{
    const std::string pkgName = "pkgNametest";
    const std::string deleteInfo = "deleteInfotest";
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
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
HWTEST_F(DeviceManagerServiceThreeTest, RegisterCredentialCallback_301, testing::ext::TestSize.Level1)
{
    const std::string pkgName = "pkgNametest";
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().RegisterCredentialCallback(pkgName);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, BindDevice_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "com.ohos.test";
    int32_t authType = 1;
    std::string deviceId = "1234";
    std::string bindParam;
    EXPECT_CALL(*permissionManagerMock_, CheckNewPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().BindDevice(pkgName, authType, deviceId, bindParam);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, UnBindDevice_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "com.ohos.test";
    std::string deviceId = "1234";
    EXPECT_CALL(*permissionManagerMock_, CheckNewPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().UnBindDevice(pkgName, deviceId);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, MineRequestCredential_301, testing::ext::TestSize.Level1)
{
    DeviceManagerService::GetInstance().isImplsoLoaded_ = false;
    std::string pkgName;
    std::string returnJsonStr;
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().MineRequestCredential(pkgName, returnJsonStr);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, CheckCredential_301, testing::ext::TestSize.Level1)
{
    std::string pkgName;
    std::string returnJsonStr;
    std::string reqJsonStr;
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().CheckCredential(pkgName, reqJsonStr, returnJsonStr);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, RegisterUiStateCallback_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "pkgName";
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().RegisterUiStateCallback(pkgName);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, UnRegisterUiStateCallback_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "pkgName";
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().UnRegisterUiStateCallback(pkgName);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, NotifyEvent_301, testing::ext::TestSize.Level1)
{
    std::string pkgName;
    int32_t eventId = 0;
    std::string event;
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().NotifyEvent(pkgName, eventId, event);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, BindTarget_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "pkgName";
    PeerTargetId targetId;
    std::map<std::string, std::string> bindParam;
    EXPECT_CALL(*permissionManagerMock_, CheckNewPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().BindTarget(pkgName, targetId, bindParam);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);

    bindParam.insert(std::make_pair(PARAM_KEY_META_TYPE, pkgName));
    EXPECT_CALL(*permissionManagerMock_, CheckNewPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceAdapterResidentLoad()).WillOnce(Return(false));
    ret = DeviceManagerService::GetInstance().BindTarget(pkgName, targetId, bindParam);
    EXPECT_EQ(ret, ERR_DM_UNSUPPORTED_METHOD);
}

HWTEST_F(DeviceManagerServiceThreeTest, DpAclAdd_301, testing::ext::TestSize.Level1)
{
    std::string udid = "udid";
    EXPECT_CALL(*permissionManagerMock_, CheckNewPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().DpAclAdd(udid);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, IsSameAccount_301, testing::ext::TestSize.Level1)
{
    std::string udid = "udidTest";
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
    EXPECT_CALL(*softbusListenerMock_, GetUdidByNetworkId(_, _)).WillOnce(Return(DM_OK));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().IsSameAccount(udid);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, CheckIsSameAccount_301, testing::ext::TestSize.Level1)
{
    DmAccessCaller caller;
    DmAccessCallee callee;
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    bool ret = DeviceManagerService::GetInstance().CheckIsSameAccount(caller, callee);
    EXPECT_FALSE(ret);
}

HWTEST_F(DeviceManagerServiceThreeTest, CheckAccessControl_301, testing::ext::TestSize.Level1)
{
    DmAccessCaller caller;
    DmAccessCallee callee;
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    bool ret = DeviceManagerService::GetInstance().CheckAccessControl(caller, callee);
    EXPECT_FALSE(ret);
}

HWTEST_F(DeviceManagerServiceThreeTest, StopAuthenticateDevice_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "pkgName_003";
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().StopAuthenticateDevice(pkgName);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, ImportAuthCode_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "pkgName";
    std::string authCode = "authCode";
    EXPECT_CALL(*permissionManagerMock_, CheckNewPermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*permissionManagerMock_, GetCallerProcessName(_)).WillOnce(Return(DM_OK));
    EXPECT_CALL(*permissionManagerMock_, CheckProcessNameValidOnAuthCode(_)).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().ImportAuthCode(pkgName, authCode);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);

    std::vector<DmDeviceInfo> deviceList;
    DmDeviceInfo dmDeviceInfo;
    dmDeviceInfo.authForm = DmAuthForm::ACROSS_ACCOUNT;
    deviceList.push_back(dmDeviceInfo);
    DeviceManagerService::GetInstance().softbusListener_ = std::make_shared<SoftbusListener>();
    EXPECT_CALL(*deviceManagerServiceMock_, GetTrustedDeviceList(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(deviceList), Return(DM_OK)));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    DeviceManagerService::GetInstance().LoadHardwareFwkService();
}

HWTEST_F(DeviceManagerServiceThreeTest, ExportAuthCode_301, testing::ext::TestSize.Level1)
{
    std::string authCode = "authCode";
    EXPECT_CALL(*permissionManagerMock_, CheckNewPermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*permissionManagerMock_, GetCallerProcessName(_)).WillOnce(Return(DM_OK));
    EXPECT_CALL(*permissionManagerMock_, CheckProcessNameValidOnAuthCode(_)).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().ExportAuthCode(authCode);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);

    int32_t userId = 0;
    std::string accountId;
    std::string accountName;
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    DeviceManagerService::GetInstance().HandleAccountLogout(userId, accountId, accountName);

    int32_t curUserId = 0;
    int32_t preUserId = 1;
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    DeviceManagerService::GetInstance().HandleUserSwitched(curUserId, preUserId);

    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    DeviceManagerService::GetInstance().HandleUserRemoved(preUserId);
}

HWTEST_F(DeviceManagerServiceThreeTest, UnbindTarget_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "pkgName";
    PeerTargetId targetId;
    std::map<std::string, std::string> unbindParam;
    EXPECT_CALL(*permissionManagerMock_, CheckNewPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceAdapterResidentLoad()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().UnbindTarget(pkgName, targetId, unbindParam);
    EXPECT_EQ(ret, ERR_DM_UNSUPPORTED_METHOD);
}

HWTEST_F(DeviceManagerServiceThreeTest, SetDnPolicy_301, testing::ext::TestSize.Level1)
{
    SetSetDnPolicyPermission();
    std::string packName = "com.ohos.test";
    std::map<std::string, std::string> policy;
    policy[PARAM_KEY_POLICY_STRATEGY_FOR_BLE] = "100";
    policy[PARAM_KEY_POLICY_TIME_OUT] = "10";
    std::string processName = "collaboration_service";
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*permissionManagerMock_, GetCallerProcessName(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(processName), Return(DM_OK)));
    EXPECT_CALL(*permissionManagerMock_, CheckProcessNameValidOnSetDnPolicy(_)).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceAdapterResidentLoad()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().SetDnPolicy(packName, policy);
    ASSERT_EQ(ret, ERR_DM_UNSUPPORTED_METHOD);

    std::string msg = "msg";
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    DeviceManagerService::GetInstance().HandleDeviceTrustedChange(msg);
}

HWTEST_F(DeviceManagerServiceThreeTest, UnBindDevice_302, testing::ext::TestSize.Level1)
{
    std::string pkgName = "com.ohos.test";
    std::string deviceId = "1234";
    std::string extra;
    EXPECT_CALL(*permissionManagerMock_, CheckNewPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().UnBindDevice(pkgName, deviceId, extra);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
}

HWTEST_F(DeviceManagerServiceThreeTest, RegisterAuthenticationType_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "pkgName";
    std::map<std::string, std::string> authParam;
    authParam.insert(std::make_pair(DM_AUTHENTICATION_TYPE, "123456"));
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().RegisterAuthenticationType(pkgName, authParam);
    EXPECT_EQ(ret, ERR_DM_INIT_FAILED);
}

HWTEST_F(DeviceManagerServiceThreeTest, GetDeviceProfileInfoList_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "pkgName";
    DmDeviceProfileInfoFilterOptions filterOptions;
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceAdapterResidentLoad()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().GetDeviceProfileInfoList(pkgName, filterOptions);
    EXPECT_EQ(ret, ERR_DM_UNSUPPORTED_METHOD);
}

HWTEST_F(DeviceManagerServiceThreeTest, GetDeviceIconInfo_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "pkgName";
    DmDeviceIconInfoFilterOptions filterOptions;
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceAdapterResidentLoad()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().GetDeviceIconInfo(pkgName, filterOptions);
    EXPECT_EQ(ret, ERR_DM_UNSUPPORTED_METHOD);
}

HWTEST_F(DeviceManagerServiceThreeTest, GetDeviceInfo_301, testing::ext::TestSize.Level1)
{
    std::string networkId = "networkId";
    DmDeviceInfo deviceInfo;
    DeviceManagerService::GetInstance().softbusListener_ = std::make_shared<SoftbusListener>();
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
    EXPECT_CALL(*softbusListenerMock_, GetUdidByNetworkId(_, _)).WillOnce(Return(DM_OK));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().GetDeviceInfo(networkId, deviceInfo);
    EXPECT_EQ(ret, ERR_DM_NOT_INIT);
    DeviceManagerService::GetInstance().softbusListener_ = nullptr;
}

HWTEST_F(DeviceManagerServiceThreeTest, PutDeviceProfileInfoList_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "pkgName";
    std::vector<DmDeviceProfileInfo> deviceProfileInfoList;
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceAdapterResidentLoad()).WillOnce(Return(false));
    EXPECT_CALL(*permissionManagerMock_, CheckProcessNameValidPutDeviceProfileInfoList(_)).WillOnce(Return(true));
    int32_t ret = DeviceManagerService::GetInstance().PutDeviceProfileInfoList(pkgName, deviceProfileInfoList);
    EXPECT_NE(ret, DM_OK);
}

HWTEST_F(DeviceManagerServiceThreeTest, GetDeviceNamePrefixs_301, testing::ext::TestSize.Level1)
{
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceAdapterResidentLoad()).WillOnce(Return(false));
    auto ret = DeviceManagerService::GetInstance().GetDeviceNamePrefixs();
    EXPECT_TRUE(ret.empty());
}

HWTEST_F(DeviceManagerServiceThreeTest, SetLocalDeviceName_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "pkgName";
    std::string deviceName = "deviceName";
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
    EXPECT_CALL(*permissionManagerMock_, GetCallerProcessName(_)).WillOnce(Return(DM_OK));
    EXPECT_CALL(*permissionManagerMock_, CheckProcessNameValidModifyLocalDeviceName(_)).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceAdapterResidentLoad()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().SetLocalDeviceName(pkgName, deviceName);
    EXPECT_EQ(ret, ERR_DM_UNSUPPORTED_METHOD);
}

HWTEST_F(DeviceManagerServiceThreeTest, SetRemoteDeviceName_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "pkgName";
    std::string deviceName = "deviceName";
    std::string deviceId = "d*********3";
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
    EXPECT_CALL(*permissionManagerMock_, GetCallerProcessName(_)).WillOnce(Return(DM_OK));
    EXPECT_CALL(*permissionManagerMock_, CheckProcessNameValidModifyRemoteDeviceName(_)).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceAdapterResidentLoad()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().SetRemoteDeviceName(pkgName, deviceId, deviceName);
    EXPECT_EQ(ret, ERR_DM_UNSUPPORTED_METHOD);
}

HWTEST_F(DeviceManagerServiceThreeTest, GetDeviceNetworkIdList_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "pkgName";
    NetworkIdQueryFilter queryFilter;
    std::vector<std::string> networkIds{"uehd*****87"};
    EXPECT_CALL(*permissionManagerMock_, CheckPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceAdapterResidentLoad()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().GetDeviceNetworkIdList(pkgName, queryFilter, networkIds);
    EXPECT_EQ(ret, ERR_DM_UNSUPPORTED_METHOD);
}

HWTEST_F(DeviceManagerServiceThreeTest, OnPinHolderSessionOpened_001, testing::ext::TestSize.Level1)
{
    DeviceManagerService::GetInstance().isImplsoLoaded_ = false;
    int sessionId = 0;
    int result = 0;
    void *data = nullptr;
    unsigned int dataLen = 0;
    int ret = DeviceManagerService::GetInstance().OnPinHolderSessionOpened(sessionId, result);
    DeviceManagerService::GetInstance().OnPinHolderBytesReceived(sessionId, data, dataLen);
    DeviceManagerService::GetInstance().OnPinHolderSessionClosed(sessionId);
    EXPECT_NE(ret, DM_OK);
}

HWTEST_F(DeviceManagerServiceThreeTest, IsDMImplSoLoaded_001, testing::ext::TestSize.Level1)
{
    DeviceManagerService::GetInstance().isImplsoLoaded_ = false;
    bool ret = DeviceManagerService::GetInstance().IsDMImplSoLoaded();
    EXPECT_FALSE(ret);
}

HWTEST_F(DeviceManagerServiceThreeTest, DmHiDumper_001, testing::ext::TestSize.Level1)
{
    std::vector<std::string> args;
    std::string result;
    int32_t ret = DeviceManagerService::GetInstance().DmHiDumper(args, result);
    EXPECT_EQ(ret, DM_OK);
}

HWTEST_F(DeviceManagerServiceThreeTest, GenerateEncryptedUuid_001, testing::ext::TestSize.Level1)
{
    std::string pkgName;
    std::string uuid;
    std::string appId;
    std::string encryptedUuid;
    int32_t ret = DeviceManagerService::GetInstance().GenerateEncryptedUuid(pkgName, uuid, appId, encryptedUuid);
    EXPECT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DeviceManagerServiceThreeTest, GenerateEncryptedUuid_002, testing::ext::TestSize.Level1)
{
    std::string pkgName = "pkgName";
    std::string uuid;
    std::string appId;
    std::string encryptedUuid;
    int32_t ret = DeviceManagerService::GetInstance().GenerateEncryptedUuid(pkgName, uuid, appId, encryptedUuid);
    EXPECT_EQ(ret, DM_OK);
}

HWTEST_F(DeviceManagerServiceThreeTest, HandleDeviceStatusChange_001, testing::ext::TestSize.Level1)
{
    DmDeviceState devState = DmDeviceState::DEVICE_INFO_READY;
    DmDeviceInfo devInfo;
    DeviceManagerService::GetInstance().HandleDeviceStatusChange(devState, devInfo);
    EXPECT_EQ(DeviceManagerService::GetInstance().softbusListener_, nullptr);
}

HWTEST_F(DeviceManagerServiceThreeTest, SendAppUnBindBroadCast_001, testing::ext::TestSize.Level1)
{
    std::vector<std::string> peerUdids;
    int32_t userId = 12;
    uint64_t tokenId = 23;
    DeviceManagerService::GetInstance().softbusListener_ = std::make_shared<SoftbusListener>();
    DeviceManagerService::GetInstance().SendAppUnBindBroadCast(peerUdids, userId, tokenId);
    EXPECT_NE(DeviceManagerService::GetInstance().softbusListener_, nullptr);
    DeviceManagerService::GetInstance().softbusListener_ = nullptr;
}

HWTEST_F(DeviceManagerServiceThreeTest, SendAppUnBindBroadCast_002, testing::ext::TestSize.Level1)
{
    std::vector<std::string> peerUdids;
    int32_t userId = 12;
    uint64_t peerTokenId = 3;
    uint64_t tokenId = 23;
    DeviceManagerService::GetInstance().softbusListener_ = std::make_shared<SoftbusListener>();
    DeviceManagerService::GetInstance().SendAppUnBindBroadCast(peerUdids, userId, tokenId, peerTokenId);
    EXPECT_NE(DeviceManagerService::GetInstance().softbusListener_, nullptr);
    DeviceManagerService::GetInstance().softbusListener_ = nullptr;
}

HWTEST_F(DeviceManagerServiceThreeTest, SendServiceUnBindBroadCast_001, testing::ext::TestSize.Level1)
{
    std::vector<std::string> peerUdids;
    int32_t userId = 12;
    uint64_t tokenId = 23;
    DeviceManagerService::GetInstance().softbusListener_ = std::make_shared<SoftbusListener>();
    DeviceManagerService::GetInstance().SendServiceUnBindBroadCast(peerUdids, userId, tokenId);
    EXPECT_NE(DeviceManagerService::GetInstance().softbusListener_, nullptr);
    DeviceManagerService::GetInstance().softbusListener_ = nullptr;
}

HWTEST_F(DeviceManagerServiceThreeTest, ClearDiscoveryCache_001, testing::ext::TestSize.Level1)
{
    ProcessInfo processInfo;
    processInfo.pkgName = "pkgName001";
    DeviceManagerService::GetInstance().InitDMServiceListener();
    DeviceManagerService::GetInstance().ClearDiscoveryCache(processInfo);
    EXPECT_NE(DeviceManagerService::GetInstance().discoveryMgr_, nullptr);
    DeviceManagerService::GetInstance().UninitDMServiceListener();
}

HWTEST_F(DeviceManagerServiceThreeTest, GetProxyInfosByParseExtra_001, testing::ext::TestSize.Level1)
{
    std::string pkgName = "pkgName";
    std::string extra = "extra";
    std::vector<std::pair<int64_t, int64_t>> agentToProxyVec;
    std::set<std::pair<std::string, std::string>> proxyInfos;
    DeviceManagerService::GetInstance().InitDMServiceListener();
    proxyInfos = DeviceManagerService::GetInstance().GetProxyInfosByParseExtra(pkgName, extra, agentToProxyVec);
    DeviceManagerService::GetInstance().UninitDMServiceListener();
    EXPECT_NE(proxyInfos.empty(), true);
}

HWTEST_F(DeviceManagerServiceThreeTest, ImportAuthCode_302, testing::ext::TestSize.Level1)
{
    std::string pkgName;
    std::string authCode;
    EXPECT_CALL(*permissionManagerMock_, CheckNewPermission()).WillOnce(Return(true));
    EXPECT_CALL(*permissionManagerMock_, GetCallerProcessName(_)).WillOnce(Return(DM_OK));
    EXPECT_CALL(*permissionManagerMock_, CheckProcessNameValidOnAuthCode(_)).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().ImportAuthCode(pkgName, authCode);
    EXPECT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DeviceManagerServiceThreeTest, ImportAuthCode_303, testing::ext::TestSize.Level1)
{
    std::string pkgName;
    std::string authCode;
    EXPECT_CALL(*permissionManagerMock_, CheckNewPermission()).WillOnce(Return(true));
    EXPECT_CALL(*permissionManagerMock_, GetCallerProcessName(_)).WillOnce(Return(ERR_DM_FAILED));
    int32_t ret = DeviceManagerService::GetInstance().ImportAuthCode(pkgName, authCode);
    EXPECT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DeviceManagerServiceThreeTest, ImportAuthCode_304, testing::ext::TestSize.Level1)
{
    std::string pkgName;
    std::string authCode;
    EXPECT_CALL(*permissionManagerMock_, CheckNewPermission()).WillOnce(Return(true));
    EXPECT_CALL(*permissionManagerMock_, GetCallerProcessName(_)).WillOnce(Return(DM_OK));
    EXPECT_CALL(*permissionManagerMock_, CheckProcessNameValidOnAuthCode(_)).WillOnce(Return(true));
    int32_t ret = DeviceManagerService::GetInstance().ImportAuthCode(pkgName, authCode);
    EXPECT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DeviceManagerServiceThreeTest, ValidateUnBindDeviceParams_301, testing::ext::TestSize.Level1)
{
    std::string pkgName = "ohos.test.pkgName";
    std::string deviceId = "deviceId";
    EXPECT_CALL(*permissionManagerMock_, CheckNewPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(ERR_DM_FAILED));
    int32_t ret = DeviceManagerService::GetInstance().ValidateUnBindDeviceParams(pkgName, deviceId);
    EXPECT_EQ(ret, DM_OK);
}

HWTEST_F(DeviceManagerServiceThreeTest, ValidateUnBindDeviceParams_302, testing::ext::TestSize.Level1)
{
    std::string pkgName = "ohos.test.pkgName";
    std::string deviceId = "deviceId";
    std::string extra;
    EXPECT_CALL(*permissionManagerMock_, CheckNewPermission()).WillOnce(Return(true));
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(ERR_DM_FAILED));
    int32_t ret = DeviceManagerService::GetInstance().ValidateUnBindDeviceParams(pkgName, deviceId, extra);
    EXPECT_EQ(ret, DM_OK);
}

HWTEST_F(DeviceManagerServiceThreeTest, ProcessUninstApp_301, testing::ext::TestSize.Level1)
{
    int32_t userId = 100;
    int32_t tokenId = 200;
    DeviceManagerService::GetInstance().softbusListener_ = std::make_shared<SoftbusListener>();
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    DeviceManagerService::GetInstance().ProcessUninstApp(userId, tokenId);
    EXPECT_NE(DeviceManagerService::GetInstance().softbusListener_, nullptr);
    DeviceManagerService::GetInstance().softbusListener_ = nullptr;
}

HWTEST_F(DeviceManagerServiceThreeTest, ProcessUnBindApp_301, testing::ext::TestSize.Level1)
{
    int32_t userId = 100;
    int32_t tokenId = 200;
    std::string extra;
    std::string udid = "ohos.test.udid";
    DeviceManagerService::GetInstance().softbusListener_ = std::make_shared<SoftbusListener>();
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    DeviceManagerService::GetInstance().ProcessUnBindApp(userId, tokenId, extra, udid);
    EXPECT_NE(DeviceManagerService::GetInstance().softbusListener_, nullptr);
    DeviceManagerService::GetInstance().softbusListener_ = nullptr;
}

HWTEST_F(DeviceManagerServiceThreeTest, CalculateBroadCastDelayTime_001, testing::ext::TestSize.Level1)
{
    DeviceManagerService::GetInstance().SendLastBroadCastTime_ = 10;
    int32_t delayTime = DeviceManagerService::GetInstance().CalculateBroadCastDelayTime();
    EXPECT_NE(delayTime, SEND_DELAY_MAX_TIME);
}

HWTEST_F(DeviceManagerServiceThreeTest, CalculateBroadCastDelayTime_002, testing::ext::TestSize.Level1)
{
    int32_t delayTime = DeviceManagerService::GetInstance().CalculateBroadCastDelayTime();
    EXPECT_NE(delayTime, SEND_DELAY_MAX_TIME);
}
HWTEST_F(DeviceManagerServiceThreeTest, ParseRelationShipChangeType_001, testing::ext::TestSize.Level1)
{
    RelationShipChangeMsg msg;
    msg.type = RelationShipChangeType::APP_UNINSTALL;
    auto ret = DeviceManagerService::GetInstance().ParseRelationShipChangeType(msg);
    EXPECT_EQ(ret, true);
}

HWTEST_F(DeviceManagerServiceThreeTest, SubscribePackageCommonEvent_301, testing::ext::TestSize.Level1)
{
    DeviceManagerService::GetInstance().packageCommonEventManager_ = std::make_shared<DmPackageCommonEventManager>();
    DeviceManagerService::GetInstance().softbusListener_ = std::make_shared<SoftbusListener>();
    EXPECT_NE(DeviceManagerService::GetInstance().softbusListener_, nullptr);
    DeviceManagerService::GetInstance().softbusListener_ = nullptr;

}

HWTEST_F(DeviceManagerServiceThreeTest, SubscribePackageCommonEvent_302, testing::ext::TestSize.Level1)
{
    DeviceManagerService::GetInstance().packageCommonEventManager_ = std::make_shared<DmPackageCommonEventManager>();
    DeviceManagerService::GetInstance().softbusListener_ = std::make_shared<SoftbusListener>();
    EXPECT_NE(DeviceManagerService::GetInstance().softbusListener_, nullptr);
    DeviceManagerService::GetInstance().softbusListener_ = nullptr;
}

HWTEST_F(DeviceManagerServiceThreeTest, SubscribePackageCommonEvent_303, testing::ext::TestSize.Level1)
{
    DeviceManagerService::GetInstance().packageCommonEventManager_ = nullptr;
    DeviceManagerService::GetInstance().softbusListener_ = std::make_shared<SoftbusListener>();
    EXPECT_NE(DeviceManagerService::GetInstance().softbusListener_, nullptr);
    DeviceManagerService::GetInstance().softbusListener_ = nullptr;
}

HWTEST_F(DeviceManagerServiceThreeTest, SubscribePackageCommonEvent_304, testing::ext::TestSize.Level1)
{
    DeviceManagerService::GetInstance().packageCommonEventManager_ = nullptr;
    DeviceManagerService::GetInstance().softbusListener_ = std::make_shared<SoftbusListener>();
    EXPECT_NE(DeviceManagerService::GetInstance().softbusListener_, nullptr);
    DeviceManagerService::GetInstance().softbusListener_ = nullptr;
}

HWTEST_F(DeviceManagerServiceThreeTest, NotifyRemoteUninstallApp_301, testing::ext::TestSize.Level1)
{
    int32_t userId = 100;
    int32_t tokenId = 200;
    DeviceManagerService::GetInstance().softbusListener_ = std::make_shared<SoftbusListener>();
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    DeviceManagerService::GetInstance().NotifyRemoteUninstallApp(userId, tokenId);
    EXPECT_NE(DeviceManagerService::GetInstance().softbusListener_, nullptr);
    DeviceManagerService::GetInstance().softbusListener_ = nullptr;
}

HWTEST_F(DeviceManagerServiceThreeTest, NotifyRemoteUninstallApp_302, testing::ext::TestSize.Level1)
{
    int32_t userId = 100;
    int32_t tokenId = 200;
    DeviceManagerService::GetInstance().softbusListener_ = nullptr;
    EXPECT_CALL(*deviceManagerServiceMock_, IsDMServiceImplReady()).WillOnce(Return(false));
    DeviceManagerService::GetInstance().NotifyRemoteUninstallApp(userId, tokenId);
    EXPECT_EQ(DeviceManagerService::GetInstance().softbusListener_, nullptr);
}

HWTEST_F(DeviceManagerServiceThreeTest, NotifyRemoteUninstallAppByWifi_001, testing::ext::TestSize.Level1)
{
    int32_t userId = 100;
    int32_t tokenId = 200;
    std::map<std::string, std::string> wifiDevices;
    DeviceManagerService::GetInstance().timer_ = nullptr;
    DeviceManagerService::GetInstance().NotifyRemoteUninstallAppByWifi(userId, tokenId, wifiDevices);
    EXPECT_EQ(DeviceManagerService::GetInstance().timer_, nullptr);
}

HWTEST_F(DeviceManagerServiceThreeTest, NotifyRemoteUninstallAppByWifi_002, testing::ext::TestSize.Level1)
{
    int32_t userId = 100;
    int32_t tokenId = 200;
    std::map<std::string, std::string> wifiDevices;
    DeviceManagerService::GetInstance().timer_ = std::make_shared<DmTimer>();
    DeviceManagerService::GetInstance().NotifyRemoteUninstallAppByWifi(userId, tokenId, wifiDevices);
    EXPECT_NE(DeviceManagerService::GetInstance().timer_, nullptr);
}

HWTEST_F(DeviceManagerServiceThreeTest, NotifyRemoteUninstallAppByWifi_003, testing::ext::TestSize.Level1)
{
    int32_t userId = 100;
    int32_t tokenId = 200;
    std::map<std::string, std::string> wifiDevices;
    DeviceManagerService::GetInstance().timer_ = nullptr;
    DeviceManagerService::GetInstance().NotifyRemoteUninstallAppByWifi(userId, tokenId, wifiDevices);
    EXPECT_EQ(DeviceManagerService::GetInstance().timer_, nullptr);
}

HWTEST_F(DeviceManagerServiceThreeTest, NotifyRemoteUnBindAppByWifi_001, testing::ext::TestSize.Level1)
{
    int32_t userId = 100;
    int32_t tokenId = 200;
    std::map<std::string, std::string> wifiDevices;
    std::string extra;
    DeviceManagerService::GetInstance().timer_ = std::make_shared<DmTimer>();
    DeviceManagerService::GetInstance().NotifyRemoteUnBindAppByWifi(userId, tokenId, extra, wifiDevices);
    EXPECT_NE(DeviceManagerService::GetInstance().timer_, nullptr);
}

HWTEST_F(DeviceManagerServiceThreeTest, ProcessReceiveRspAppUninstall_301, testing::ext::TestSize.Level1)
{
   std::string remoteUdid = "ohos";
   DeviceManagerService::GetInstance().timer_ = std::make_shared<DmTimer>();
   DeviceManagerService::GetInstance().ProcessReceiveRspAppUninstall(remoteUdid);
   EXPECT_NE(DeviceManagerService::GetInstance().timer_, nullptr);
}

HWTEST_F(DeviceManagerServiceThreeTest, ProcessReceiveRspAppUninstall_302, testing::ext::TestSize.Level1)
{
   std::string remoteUdid = "ohos";
   DeviceManagerService::GetInstance().timer_ = nullptr;
   DeviceManagerService::GetInstance().ProcessReceiveRspAppUninstall(remoteUdid);
   EXPECT_EQ(DeviceManagerService::GetInstance().timer_, nullptr);
}

HWTEST_F(DeviceManagerServiceThreeTest, ProcessReceiveRspAppUnbind_301, testing::ext::TestSize.Level1)
{
    std::string remoteUdid = "ohos";
    DeviceManagerService::GetInstance().timer_ = std::make_shared<DmTimer>();
    DeviceManagerService::GetInstance().ProcessReceiveRspAppUnbind(remoteUdid);
    EXPECT_NE(DeviceManagerService::GetInstance().timer_, nullptr);
}

HWTEST_F(DeviceManagerServiceThreeTest, ProcessReceiveRspAppUnbind_302, testing::ext::TestSize.Level1)
{
    std::string remoteUdid = "ohos";
    DeviceManagerService::GetInstance().timer_ = nullptr;
    DeviceManagerService::GetInstance().ProcessReceiveRspAppUnbind(remoteUdid);
    EXPECT_EQ(DeviceManagerService::GetInstance().timer_, nullptr);
}
} // namespace
} // namespace DistributedHardware
} // namespace OHOS
