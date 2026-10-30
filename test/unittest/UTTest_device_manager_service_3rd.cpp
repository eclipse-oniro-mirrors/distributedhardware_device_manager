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

#include "UTTest_device_manager_service_3rd.h"
#include "accesstoken_kit.h"
#include "dm_constants.h"
#include "dm_device_info.h"
#include "dm_error_type.h"
#include "dm_log.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace OHOS::Security::AccessToken;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
DM_IMPLEMENT_SINGLE_INSTANCE(DeviceManagerService);

namespace {
void ResetServiceTimer()
{
    auto &service = DeviceManagerService::GetInstance();
    std::shared_ptr<DmTimer> timer;
    {
        std::lock_guard<std::mutex> lock(service.timerLocks_);
        timer.swap(service.timer_);
    }
    if (timer != nullptr) {
        timer->DeleteAll();
    }
}
}

void DeviceManagerService3rdTest::SetUp()
{
    ResetServiceTimer();
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
    Dm3rdDeviceCache::GetInstance().DeleteAll3rdDeviceInfo();
}

void DeviceManagerService3rdTest::TearDown()
{
    ResetServiceTimer();
    Dm3rdDeviceCache::GetInstance().DeleteAll3rdDeviceInfo();
    DeviceManagerService::GetInstance().softbusListener_ = nullptr;
    Mock::VerifyAndClearExpectations(permissionManagerMock_.get());
    Mock::VerifyAndClearExpectations(softbusListenerMock_.get());
    Mock::VerifyAndClearExpectations(kVAdapterManagerMock_.get());
    Mock::VerifyAndClearExpectations(appManagerMock_.get());
    Mock::VerifyAndClearExpectations(deviceManagerServiceImplMock_.get());
    Mock::VerifyAndClearExpectations(softbusCacheMock_.get());
    Mock::VerifyAndClearExpectations(cryptoMock_.get());
    Mock::VerifyAndClearExpectations(multipleUserConnectorMock_.get());
    Mock::VerifyAndClearExpectations(dMCommToolMock_.get());
    Mock::VerifyAndClearExpectations(deviceProfileConnectorMock_.get());
    Mock::VerifyAndClearExpectations(deviceNameManagerMock_.get());
    Mock::VerifyAndClearExpectations(dmConstrainsManagerMock_.get());
}

void DeviceManagerService3rdTest::SetUpTestCase()
{
    DmPermissionManager::dmPermissionManager = permissionManagerMock_;
    DmSoftbusListener::dmSoftbusListener = softbusListenerMock_;
    DmKVAdapterManager::dmKVAdapterManager = kVAdapterManagerMock_;
    DmAppManager::dmAppManager = appManagerMock_;
    DmDeviceManagerServiceImpl::dmDeviceManagerServiceImpl = deviceManagerServiceImplMock_;
    DmSoftbusCache::dmSoftbusCache = softbusCacheMock_;
    DmCrypto::dmCrypto = cryptoMock_;
    DmMultipleUserConnector::dmMultipleUserConnector = multipleUserConnectorMock_;
    DmDMCommTool::dmDMCommTool = dMCommToolMock_;
    DmDeviceProfileConnector::dmDeviceProfileConnector = deviceProfileConnectorMock_;
    DmDeviceNameManager::dmDeviceNameManager_ = deviceNameManagerMock_;
    DmDmConstrainsManager::dmConstrainsManager = dmConstrainsManagerMock_;
}

void DeviceManagerService3rdTest::TearDownTestCase()
{
    DmPermissionManager::dmPermissionManager = nullptr;
    permissionManagerMock_ = nullptr;
    DmSoftbusListener::dmSoftbusListener = nullptr;
    softbusListenerMock_ = nullptr;
    DmKVAdapterManager::dmKVAdapterManager = nullptr;
    kVAdapterManagerMock_ = nullptr;
    DmAppManager::dmAppManager = nullptr;
    appManagerMock_ = nullptr;
    DmDeviceManagerServiceImpl::dmDeviceManagerServiceImpl = nullptr;
    deviceManagerServiceImplMock_ = nullptr;
    DmSoftbusCache::dmSoftbusCache = nullptr;
    softbusCacheMock_ = nullptr;
    DmCrypto::dmCrypto = nullptr;
    cryptoMock_ = nullptr;
    DmMultipleUserConnector::dmMultipleUserConnector = nullptr;
    multipleUserConnectorMock_ = nullptr;
    DmDMCommTool::dmDMCommTool = nullptr;
    dMCommToolMock_ = nullptr;
    DmDeviceProfileConnector::dmDeviceProfileConnector = nullptr;
    deviceProfileConnectorMock_ = nullptr;
    DmDeviceNameManager::dmDeviceNameManager_ = nullptr;
    deviceNameManagerMock_ = nullptr;
    DmDmConstrainsManager::dmConstrainsManager = nullptr;
    dmConstrainsManagerMock_ = nullptr;
}

namespace {
Dm3rdDeviceInfo Build3rdInfo(const std::string &networkId, const std::string &deviceName)
{
    Dm3rdDeviceInfo info;
    info.networkId = networkId;
    info.deviceName = deviceName;
    info.extendParam["symbolName"] = "symbol3rd";
    return info;
}

void GrantPermissionAndSystemCaller()
{
    EXPECT_CALL(*DeviceManagerService3rdTest::permissionManagerMock_, CheckAccessServicePermission())
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*DeviceManagerService3rdTest::appManagerMock_, IsSystemSA()).WillRepeatedly(Return(true));
}
}

/**
 * @tc.name: Register3rdDeviceInfo_001
 * @tc.desc: register 3rd device without permission
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerService3rdTest, Register3rdDeviceInfo_001, testing::ext::TestSize.Level1)
{
    EXPECT_CALL(*permissionManagerMock_, CheckAccessServicePermission()).WillRepeatedly(Return(false));
    Dm3rdDeviceInfo info = Build3rdInfo("networkId_3rd_001", "deviceName_3rd");
    int32_t ret = DeviceManagerService::GetInstance().Register3rdDeviceInfo(info);
    EXPECT_EQ(ret, ERR_DM_NO_PERMISSION);
}

/**
 * @tc.name: Register3rdDeviceInfo_002
 * @tc.desc: register 3rd device with permission but not system sa or system app
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerService3rdTest, Register3rdDeviceInfo_002, testing::ext::TestSize.Level1)
{
    EXPECT_CALL(*permissionManagerMock_, CheckAccessServicePermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*appManagerMock_, IsSystemSA()).WillRepeatedly(Return(false));
    EXPECT_CALL(*appManagerMock_, IsSystemApp()).WillRepeatedly(Return(false));
    Dm3rdDeviceInfo info = Build3rdInfo("networkId_3rd_002", "deviceName_3rd");
    int32_t ret = DeviceManagerService::GetInstance().Register3rdDeviceInfo(info);
    EXPECT_EQ(ret, ERR_DM_NO_PERMISSION);
}

/**
 * @tc.name: Register3rdDeviceInfo_003
 * @tc.desc: register 3rd device with networkId conflicting with local device
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerService3rdTest, Register3rdDeviceInfo_003, testing::ext::TestSize.Level1)
{
    GrantPermissionAndSystemCaller();
    DmDeviceInfo localDeviceInfo;
    std::string localNetworkId = "networkId_local_conflict";
    errno_t retCpy = memcpy_s(localDeviceInfo.networkId, sizeof(localDeviceInfo.networkId),
        localNetworkId.c_str(), localNetworkId.length());
    EXPECT_EQ(retCpy, DM_OK);
    EXPECT_CALL(*softbusCacheMock_, GetLocalDeviceInfo(_))
        .WillOnce(DoAll(SetArgReferee<0>(localDeviceInfo), Return(DM_OK)));

    Dm3rdDeviceInfo info = Build3rdInfo(localNetworkId, "deviceName_3rd");
    int32_t ret = DeviceManagerService::GetInstance().Register3rdDeviceInfo(info);
    EXPECT_EQ(ret, ERR_DM_MAP_KEY_ALREADY_EXISTS);
}

/**
 * @tc.name: Register3rdDeviceInfo_004
 * @tc.desc: register 3rd device success and query hit
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerService3rdTest, Register3rdDeviceInfo_004, testing::ext::TestSize.Level1)
{
    GrantPermissionAndSystemCaller();
    Dm3rdDeviceInfo info = Build3rdInfo("networkId_3rd_004", "deviceName_3rd_004");
    int32_t ret = DeviceManagerService::GetInstance().Register3rdDeviceInfo(info);
    EXPECT_EQ(ret, DM_OK);

    DmDeviceInfo deviceInfo;
    bool isFound = Dm3rdDeviceCache::GetInstance().Get3rdDeviceInfo(info.networkId, deviceInfo);
    EXPECT_TRUE(isFound);
    EXPECT_EQ(std::string(deviceInfo.deviceName), "deviceName_3rd_004");
    EXPECT_NE(deviceInfo.extraData.find("\"SYMBOL_NAME\":\"symbol3rd\""), std::string::npos);
    EXPECT_NE(deviceInfo.extraData.find("\"DEVICE_SOURCE\":\"3RD\""), std::string::npos);
}

/**
 * @tc.name: UnRegister3rdDeviceInfo_001
 * @tc.desc: unregister 3rd device without permission or with empty networkId
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerService3rdTest, UnRegister3rdDeviceInfo_001, testing::ext::TestSize.Level1)
{
    EXPECT_CALL(*permissionManagerMock_, CheckAccessServicePermission()).WillRepeatedly(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().UnRegister3rdDeviceInfo("networkId_3rd_unreg");
    EXPECT_EQ(ret, ERR_DM_NO_PERMISSION);

    GrantPermissionAndSystemCaller();
    ret = DeviceManagerService::GetInstance().UnRegister3rdDeviceInfo("");
    EXPECT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: UnRegister3rdDeviceInfo_002
 * @tc.desc: unregister registered 3rd device by the same caller, then repeat unregister
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerService3rdTest, UnRegister3rdDeviceInfo_002, testing::ext::TestSize.Level1)
{
    GrantPermissionAndSystemCaller();
    Dm3rdDeviceInfo info = Build3rdInfo("networkId_3rd_unreg_002", "deviceName_3rd");
    EXPECT_EQ(DeviceManagerService::GetInstance().Register3rdDeviceInfo(info), DM_OK);

    int32_t ret = DeviceManagerService::GetInstance().UnRegister3rdDeviceInfo(info.networkId);
    EXPECT_EQ(ret, DM_OK);
    DmDeviceInfo deviceInfo;
    EXPECT_FALSE(Dm3rdDeviceCache::GetInstance().Get3rdDeviceInfo(info.networkId, deviceInfo));

    ret = DeviceManagerService::GetInstance().UnRegister3rdDeviceInfo(info.networkId);
    EXPECT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: GetDeviceInfo_3rd_001
 * @tc.desc: standard device info not found, fallback to 3rd device cache
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerService3rdTest, GetDeviceInfo_3rd_001, testing::ext::TestSize.Level1)
{
    GrantPermissionAndSystemCaller();
    Dm3rdDeviceInfo info = Build3rdInfo("networkId_3rd_query_001", "deviceName_3rd_query");
    EXPECT_EQ(DeviceManagerService::GetInstance().Register3rdDeviceInfo(info), DM_OK);

    DeviceManagerService::GetInstance().softbusListener_ = std::make_shared<SoftbusListener>();
    // standard query returns DM_OK with empty info, which means not found
    DmDeviceInfo deviceInfo;
    int32_t ret = DeviceManagerService::GetInstance().GetDeviceInfo(info.networkId, deviceInfo);
    EXPECT_EQ(ret, DM_OK);
    EXPECT_EQ(std::string(deviceInfo.networkId), info.networkId);
    EXPECT_EQ(std::string(deviceInfo.deviceName), "deviceName_3rd_query");
    EXPECT_NE(deviceInfo.extraData.find("\"DEVICE_SOURCE\":\"3RD\""), std::string::npos);
}

/**
 * @tc.name: GetDeviceInfo_3rd_002
 * @tc.desc: standard device info found, no fallback to 3rd device cache
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerService3rdTest, GetDeviceInfo_3rd_002, testing::ext::TestSize.Level1)
{
    GrantPermissionAndSystemCaller();
    Dm3rdDeviceInfo info = Build3rdInfo("networkId_3rd_query_002", "deviceName_3rd_query");
    EXPECT_EQ(DeviceManagerService::GetInstance().Register3rdDeviceInfo(info), DM_OK);

    DeviceManagerService::GetInstance().softbusListener_ = std::make_shared<SoftbusListener>();
    DmDeviceInfo standardInfo;
    std::string standardNetworkId = "networkId_3rd_query_002";
    errno_t retCpy = memcpy_s(standardInfo.networkId, sizeof(standardInfo.networkId),
        standardNetworkId.c_str(), standardNetworkId.length());
    EXPECT_EQ(retCpy, DM_OK);
    retCpy = memcpy_s(standardInfo.deviceName, sizeof(standardInfo.deviceName), "standardName",
        strlen("standardName"));
    EXPECT_EQ(retCpy, DM_OK);
    // standard query returns DM_OK with matched info
    EXPECT_CALL(*softbusListenerMock_, GetDeviceInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(standardInfo), Return(DM_OK)));

    DmDeviceInfo deviceInfo;
    int32_t ret = DeviceManagerService::GetInstance().GetDeviceInfo(info.networkId, deviceInfo);
    EXPECT_EQ(ret, DM_OK);
    EXPECT_EQ(std::string(deviceInfo.deviceName), "standardName");
    EXPECT_EQ(deviceInfo.extraData.find("\"DEVICE_SOURCE\":\"3RD\""), std::string::npos);
}

/**
 * @tc.name: HandleDeviceStatusChange_3rd_001
 * @tc.desc: standard device online with same networkId evicts 3rd device info
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerService3rdTest, HandleDeviceStatusChange_3rd_001, testing::ext::TestSize.Level1)
{
    GrantPermissionAndSystemCaller();
    Dm3rdDeviceInfo info = Build3rdInfo("networkId_3rd_online_001", "deviceName_3rd");
    EXPECT_EQ(DeviceManagerService::GetInstance().Register3rdDeviceInfo(info), DM_OK);

    DmDeviceInfo onlineInfo;
    std::string onlineNetworkId = "networkId_3rd_online_001";
    errno_t retCpy = memcpy_s(onlineInfo.networkId, sizeof(onlineInfo.networkId),
        onlineNetworkId.c_str(), onlineNetworkId.length());
    EXPECT_EQ(retCpy, DM_OK);
    DeviceManagerService::GetInstance().HandleDeviceStatusChange(DEVICE_STATE_ONLINE, onlineInfo, true);

    DmDeviceInfo deviceInfo;
    EXPECT_FALSE(Dm3rdDeviceCache::GetInstance().Get3rdDeviceInfo(info.networkId, deviceInfo));
}
} // namespace DistributedHardware
} // namespace OHOS
