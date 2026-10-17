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

#include "UTTest_device_manager_service.h"
#include "dm_constants.h"
#include "dm_device_info.h"
#include "dm_log.h"
#include "json_object.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {

HWTEST_F(DeviceManagerServiceTest, GetOsTypeByNetworkId_001, testing::ext::TestSize.Level1)
{
    std::string pkgName;
    std::string networkId;
    int32_t osType = 0;
    int32_t ret = DeviceManagerService::GetInstance().GetOsTypeByNetworkId(pkgName, networkId, osType);
    EXPECT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DeviceManagerServiceTest, GetOsTypeByNetworkId_002, testing::ext::TestSize.Level1)
{
    std::string pkgName = "com.ohos.test";
    std::string networkId;
    int32_t osType = 0;
    int32_t ret = DeviceManagerService::GetInstance().GetOsTypeByNetworkId(pkgName, networkId, osType);
    EXPECT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DeviceManagerServiceTest, GetOsTypeByNetworkId_003, testing::ext::TestSize.Level1)
{
    std::string pkgName;
    std::string networkId = "networkId123";
    int32_t osType = 0;
    int32_t ret = DeviceManagerService::GetInstance().GetOsTypeByNetworkId(pkgName, networkId, osType);
    EXPECT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DeviceManagerServiceTest, GetOsTypeByNetworkId_004, testing::ext::TestSize.Level1)
{
    std::string pkgName = "com.ohos.test";
    std::string networkId = "networkId123";
    int32_t osType = 0;
    EXPECT_CALL(*permissionManagerMock_, CheckAccessServicePermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*permissionManagerMock_, CheckDataSyncPermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*appManagerMock_, IsSystemApp()).WillOnce(Return(false));
    int32_t ret = DeviceManagerService::GetInstance().GetOsTypeByNetworkId(pkgName, networkId, osType);
    EXPECT_EQ(ret, ERR_DM_NOT_SYSTEM_APP);
    EXPECT_EQ(osType, -1);
}

HWTEST_F(DeviceManagerServiceTest, GetOsTypeByNetworkId_005, testing::ext::TestSize.Level1)
{
    std::string pkgName = "com.ohos.test";
    std::string networkId = "networkId123";
    int32_t osType = 0;
    EXPECT_CALL(*permissionManagerMock_, CheckAccessServicePermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*permissionManagerMock_, CheckDataSyncPermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*appManagerMock_, IsSystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*softbusCacheMock_, GetDevInfoByNetworkId(_, _)).WillOnce(Return(ERR_DM_FAILED));
    int32_t ret = DeviceManagerService::GetInstance().GetOsTypeByNetworkId(pkgName, networkId, osType);
    EXPECT_EQ(ret, ERR_DM_GET_OSTYPE_FAILED);
    EXPECT_EQ(osType, -1);
}

HWTEST_F(DeviceManagerServiceTest, GetOsTypeByNetworkId_006, testing::ext::TestSize.Level1)
{
    std::string pkgName = "com.ohos.test";
    std::string networkId = "networkId123";
    int32_t osType = 0;
    DmDeviceInfo devInfo;
    (void)memset_s(&devInfo, sizeof(DmDeviceInfo), 0, sizeof(DmDeviceInfo));
    devInfo.extraData = "";
    EXPECT_CALL(*permissionManagerMock_, CheckAccessServicePermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*permissionManagerMock_, CheckDataSyncPermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*appManagerMock_, IsSystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*softbusCacheMock_, GetDevInfoByNetworkId(_, _))
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(devInfo), Return(DM_OK)));
    int32_t ret = DeviceManagerService::GetInstance().GetOsTypeByNetworkId(pkgName, networkId, osType);
    EXPECT_EQ(ret, ERR_DM_GET_OSTYPE_FAILED);
    EXPECT_EQ(osType, -1);
}

HWTEST_F(DeviceManagerServiceTest, GetOsTypeByNetworkId_007, testing::ext::TestSize.Level1)
{
    std::string pkgName = "com.ohos.test";
    std::string networkId = "networkId123";
    int32_t osType = 0;
    DmDeviceInfo devInfo;
    (void)memset_s(&devInfo, sizeof(DmDeviceInfo), 0, sizeof(DmDeviceInfo));
    devInfo.extraData = "{\"OS_TYPE\":1}";
    EXPECT_CALL(*permissionManagerMock_, CheckAccessServicePermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*permissionManagerMock_, CheckDataSyncPermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*appManagerMock_, IsSystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*softbusCacheMock_, GetDevInfoByNetworkId(_, _))
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(devInfo), Return(DM_OK)));
    int32_t ret = DeviceManagerService::GetInstance().GetOsTypeByNetworkId(pkgName, networkId, osType);
    EXPECT_EQ(ret, DM_OK);
    EXPECT_EQ(osType, 1);
}

HWTEST_F(DeviceManagerServiceTest, GetOsTypeByNetworkId_008, testing::ext::TestSize.Level1)
{
    std::string pkgName = "com.ohos.test";
    std::string networkId = "networkId123";
    int32_t osType = 0;
    DmDeviceInfo devInfo;
    (void)memset_s(&devInfo, sizeof(DmDeviceInfo), 0, sizeof(DmDeviceInfo));
    devInfo.extraData = "{\"INVALID_KEY\":1}";
    EXPECT_CALL(*permissionManagerMock_, CheckAccessServicePermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*permissionManagerMock_, CheckDataSyncPermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*appManagerMock_, IsSystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*softbusCacheMock_, GetDevInfoByNetworkId(_, _))
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(devInfo), Return(DM_OK)));
    int32_t ret = DeviceManagerService::GetInstance().GetOsTypeByNetworkId(pkgName, networkId, osType);
    EXPECT_EQ(ret, ERR_DM_GET_OSTYPE_FAILED);
    EXPECT_EQ(osType, -1);
}

HWTEST_F(DeviceManagerServiceTest, GetOsTypeByNetworkId_009, testing::ext::TestSize.Level1)
{
    std::string pkgName = "com.ohos.test";
    std::string networkId = "networkId123";
    int32_t osType = 0;
    DmDeviceInfo devInfo;
    (void)memset_s(&devInfo, sizeof(DmDeviceInfo), 0, sizeof(DmDeviceInfo));
    devInfo.extraData = "invalid_json";
    EXPECT_CALL(*permissionManagerMock_, CheckAccessServicePermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*permissionManagerMock_, CheckDataSyncPermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*appManagerMock_, IsSystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*softbusCacheMock_, GetDevInfoByNetworkId(_, _))
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(devInfo), Return(DM_OK)));
    int32_t ret = DeviceManagerService::GetInstance().GetOsTypeByNetworkId(pkgName, networkId, osType);
    EXPECT_EQ(ret, ERR_DM_GET_OSTYPE_FAILED);
    EXPECT_EQ(osType, -1);
}

HWTEST_F(DeviceManagerServiceTest, GetOsTypeByNetworkId_010, testing::ext::TestSize.Level1)
{
    std::string pkgName = "com.ohos.test";
    std::string networkId = "networkId123";
    int32_t osType = 0;
    DmDeviceInfo devInfo;
    (void)memset_s(&devInfo, sizeof(DmDeviceInfo), 0, sizeof(DmDeviceInfo));
    devInfo.extraData = "{\"OS_TYPE\":\"invalid_type\"}";
    EXPECT_CALL(*permissionManagerMock_, CheckAccessServicePermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*permissionManagerMock_, CheckDataSyncPermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*appManagerMock_, IsSystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*softbusCacheMock_, GetDevInfoByNetworkId(_, _))
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(devInfo), Return(DM_OK)));
    int32_t ret = DeviceManagerService::GetInstance().GetOsTypeByNetworkId(pkgName, networkId, osType);
    EXPECT_EQ(ret, ERR_DM_GET_OSTYPE_FAILED);
    EXPECT_EQ(osType, -1);
}

HWTEST_F(DeviceManagerServiceTest, GetOsTypeByNetworkId_011, testing::ext::TestSize.Level1)
{
    std::string pkgName = "com.ohos.test";
    std::string networkId = "networkId123";
    int32_t osType = 0;
    DmDeviceInfo devInfo;
    (void)memset_s(&devInfo, sizeof(DmDeviceInfo), 0, sizeof(DmDeviceInfo));
    devInfo.extraData = "{\"OS_TYPE\":2}";
    EXPECT_CALL(*permissionManagerMock_, CheckAccessServicePermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*permissionManagerMock_, CheckDataSyncPermission()).WillRepeatedly(Return(true));
    EXPECT_CALL(*appManagerMock_, IsSystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*softbusCacheMock_, GetDevInfoByNetworkId(_, _))
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(devInfo), Return(DM_OK)));
    int32_t ret = DeviceManagerService::GetInstance().GetOsTypeByNetworkId(pkgName, networkId, osType);
    EXPECT_EQ(ret, DM_OK);
    EXPECT_EQ(osType, 2);
}

HWTEST_F(DeviceManagerServiceTest, GetOsTypeByNetworkId_012, testing::ext::TestSize.Level1)
{
    std::string pkgName = "com.ohos.test";
    std::string networkId = "networkId456";
    int32_t osType = 0;
    int32_t ret = DeviceManagerService::GetInstance().GetOsTypeByNetworkId(pkgName, networkId, osType);
    EXPECT_EQ(ret, ERR_DM_NO_PERMISSION);
    EXPECT_EQ(osType, -1);
}
} // namespace DistributedHardware
} // namespace OHOS