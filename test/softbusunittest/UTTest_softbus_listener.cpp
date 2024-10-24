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
#include "UTTest_softbus_listener.h"

#include <securec.h>
#include <unistd.h>
#include <cstdlib>
#include <thread>

#include "device_manager_impl.h"
#include "dm_anonymous.h"
#include "dm_constants.h"
#include "dm_device_info.h"
#include "dm_log.h"
#include "parameter.h"
#include "nlohmann/json.hpp"
#include "system_ability_definition.h"
#include "softbus_listener.cpp"
#include "softbus_error_code.h"

namespace OHOS {
namespace DistributedHardware {
void SoftbusListenerTest::SetUp()
{
}
void SoftbusListenerTest::TearDown()
{
}
void SoftbusListenerTest::SetUpTestCase()
{
}
void SoftbusListenerTest::TearDownTestCase()
{
}

namespace {
    std::shared_ptr<SoftbusListener> softbusListener = std::make_shared<SoftbusListener>();

bool checkSoftbusRes(int32_t ret)
{
    return ret == SOFTBUS_INVALID_PARAM || ret == SOFTBUS_NETWORK_NOT_INIT || ret == SOFTBUS_NETWORK_LOOPER_ERR;
}

/**
 * @tc.name: ConvertNodeBasicInfoToDmDevice_001
 * @tc.desc: go to the correct case and return DM_OK
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(SoftbusListenerTest, ConvertNodeBasicInfoToDmDevice_001, testing::ext::TestSize.Level0)
{
    NodeBasicInfo nodeBasicInfo;
    DmDeviceInfo dmDeviceInfo;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->ConvertNodeBasicInfoToDmDevice(nodeBasicInfo, dmDeviceInfo);
    EXPECT_EQ(ret, DM_OK);
}

/**
 * @tc.name: ConvertNodeBasicInfoToDmDevice_002
 * @tc.desc: return DM_OK
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusListenerTest, ConvertNodeBasicInfoToDmDevice_002, testing::ext::TestSize.Level0)
{
    NodeBasicInfo nodeBasicInfo;
    DmDeviceBasicInfo dmDevicdeviceNameeInfo;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->ConvertNodeBasicInfoToDmDevice(nodeBasicInfo, dmDevicdeviceNameeInfo);
    EXPECT_EQ(ret, DM_OK);
}

/**
 * @tc.name: OnSoftbusDeviceOnline_001
 * @tc.desc: return true
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(SoftbusListenerTest, OnSoftbusDeviceOnline_001, testing::ext::TestSize.Level0)
{
    NodeBasicInfo info = {
            .networkId = "123456",
            .deviceName = "123456",
            .deviceTypeId = 1
        };
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->OnSoftbusDeviceOnline(&info);
    softbusListener->OnSoftbusDeviceOffline(&info);
    EXPECT_EQ(softbusListener->isRadarSoLoad_, true);
}

/**
 * @tc.name: ShiftLNNGear_001
 * @tc.desc: return DM_OK
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusListenerTest, ShiftLNNGear_001, testing::ext::TestSize.Level0)
{
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    NodeBasicInfo *info = nullptr;
    softbusListener->OnSoftbusDeviceOnline(info);
    std::string callerId = "callerId";
    EXPECT_NE(softbusListener->ShiftLNNGear(false, callerId), DM_OK);
}

HWTEST_F(SoftbusListenerTest, ShiftLNNGear_002, testing::ext::TestSize.Level0)
{
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    std::string callerId;
    EXPECT_EQ(softbusListener->ShiftLNNGear(false, callerId), ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(SoftbusListenerTest, ConvertScreenStatusToDmDevice_001, testing::ext::TestSize.Level0)
{
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    NodeBasicInfo nodeInfo = {
            .networkId = "123456",
            .deviceName = "123456",
            .deviceTypeId = 1
        };
    int32_t devScreenStatus = 1;
    DmDeviceInfo devInfo = {
        .deviceId = {"45688"},
        .deviceName = {"device_001"},
        .deviceTypeId = 12,
        .extraData = "dsasweadwe65164654",
        .networkId = {"8885665"},
        .networkType = 21,
        .range = 2,
        .authForm = DmAuthForm::ACROSS_ACCOUNT
    };
    int ret = softbusListener->ConvertScreenStatusToDmDevice(nodeInfo, devScreenStatus, devInfo);
    EXPECT_EQ(ret, DM_OK);
}

HWTEST_F(SoftbusListenerTest, DeviceOnLine_001, testing::ext::TestSize.Level0)
{
    DmDeviceInfo deviceInf = {
        .deviceId = "123456",
        .deviceName = "name",
        .deviceTypeId = 1,
        .networkId = "123456",
    };
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->DeviceOnLine(deviceInf);
    softbusListener->DeviceNameChange(deviceInf);
    softbusListener->DeviceOffLine(deviceInf);
    EXPECT_EQ(softbusListener->isRadarSoLoad_, true);
}

HWTEST_F(SoftbusListenerTest, OnSoftbusDeviceInfoChanged_001, testing::ext::TestSize.Level0)
{
    NodeBasicInfoType type = NodeBasicInfoType::TYPE_DEVICE_NAME;
    NodeBasicInfo *info = nullptr;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->OnSoftbusDeviceInfoChanged(type, info);
    EXPECT_EQ(softbusListener->isRadarSoLoad_, true);
}

HWTEST_F(SoftbusListenerTest, OnSoftbusDeviceInfoChanged_002, testing::ext::TestSize.Level0)
{
    NodeBasicInfoType type = NodeBasicInfoType::TYPE_DEVICE_NAME;
    NodeBasicInfo nodeBasic;
    NodeBasicInfo *info = &nodeBasic;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->OnSoftbusDeviceInfoChanged(type, info);
    EXPECT_EQ(softbusListener->isRadarSoLoad_, true);
}

HWTEST_F(SoftbusListenerTest, OnSoftbusDeviceInfoChanged_003, testing::ext::TestSize.Level0)
{
    NodeBasicInfoType type = NodeBasicInfoType::TYPE_NETWORK_INFO;
    NodeBasicInfo nodeBasic;
    NodeBasicInfo *info = &nodeBasic;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->OnSoftbusDeviceInfoChanged(type, info);
    EXPECT_EQ(softbusListener->isRadarSoLoad_, true);
}

HWTEST_F(SoftbusListenerTest, OnSoftbusDeviceFound_001, testing::ext::TestSize.Level0)
{
    DeviceInfo *device = nullptr;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->OnSoftbusDeviceFound(device);
    EXPECT_EQ(softbusListener->isRadarSoLoad_, true);
}

HWTEST_F(SoftbusListenerTest, OnSoftbusDeviceFound_002, testing::ext::TestSize.Level0)
{
    DeviceInfo info;
    DeviceInfo *device = &info;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->OnSoftbusDeviceFound(device);
    EXPECT_EQ(softbusListener->isRadarSoLoad_, true);
}

HWTEST_F(SoftbusListenerTest, OnSoftbusDiscoveryResult_001, testing::ext::TestSize.Level0)
{
    int subscribeId = 1;
    RefreshResult result = RefreshResult::REFRESH_LNN_SUCCESS;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->OnSoftbusDiscoveryResult(subscribeId, result);
    EXPECT_EQ(softbusListener->isRadarSoLoad_, true);
}

HWTEST_F(SoftbusListenerTest, OnSoftbusPublishResult_001, testing::ext::TestSize.Level0)
{
    int subscribeId = 1;
    PublishResult result = PublishResult::PUBLISH_LNN_SUCCESS;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->OnSoftbusPublishResult(subscribeId, result);
    EXPECT_EQ(softbusListener->isRadarSoLoad_, true);
}

HWTEST_F(SoftbusListenerTest, PublishSoftbusLNN_001, testing::ext::TestSize.Level0)
{
    DmPublishInfo dmPubInfo;
    std::string capability;
    std::string customData;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->PublishSoftbusLNN(dmPubInfo, capability, customData);
    EXPECT_EQ(true, checkSoftbusRes(ret));
}

HWTEST_F(SoftbusListenerTest, StopPublishSoftbusLNN_001, testing::ext::TestSize.Level0)
{
    int32_t publishId = 1;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->StopPublishSoftbusLNN(publishId);
    EXPECT_EQ(true, checkSoftbusRes(ret));
}

HWTEST_F(SoftbusListenerTest, RegisterSoftbusLnnOpsCbk_001, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    std::shared_ptr<ISoftbusDiscoveringCallback> callback = nullptr;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->RegisterSoftbusLnnOpsCbk(pkgName, callback);
    EXPECT_EQ(ret, ERR_DM_POINT_NULL);
}

HWTEST_F(SoftbusListenerTest, RegisterSoftbusLnnOpsCbk_002, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    std::shared_ptr<ISoftbusDiscoveringCallback> callback = std::make_shared<ISoftbusDiscoveringCallbackTest>();
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->RegisterSoftbusLnnOpsCbk(pkgName, callback);
    EXPECT_EQ(ret, DM_OK);
}

HWTEST_F(SoftbusListenerTest, UnRegisterSoftbusLnnOpsCbk_001, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->UnRegisterSoftbusLnnOpsCbk(pkgName);
    EXPECT_EQ(ret, DM_OK);
}

HWTEST_F(SoftbusListenerTest, GetUdidByNetworkId_001, testing::ext::TestSize.Level0)
{
    std::string networkId = "networkId";
    std::string udid = "udid";
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->GetUdidByNetworkId(networkId.c_str(), udid);
    EXPECT_EQ(true, checkSoftbusRes(ret));
}

HWTEST_F(SoftbusListenerTest, GetUuidByNetworkId_001, testing::ext::TestSize.Level0)
{
    std::string networkId = "networkId";
    std::string udid;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->GetUuidByNetworkId(networkId.c_str(), udid);
    EXPECT_EQ(true, checkSoftbusRes(ret));
}

HWTEST_F(SoftbusListenerTest, ConvertDeviceInfoToDmDevice_001, testing::ext::TestSize.Level0)
{
    DeviceInfo device;
    DmDeviceInfo dmDevice;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->ConvertDeviceInfoToDmDevice(device, dmDevice);
    EXPECT_EQ(softbusListener->isRadarSoLoad_, true);
}

HWTEST_F(SoftbusListenerTest, ConvertDeviceInfoToDmDevice_002, testing::ext::TestSize.Level0)
{
    DmDeviceInfo dmDevice;
    DeviceInfo deviceInfo = {
        .devId = "deviceId",
        .devType = (DeviceType)1,
        .devName = "11111",
        .addrNum = 1,
        .addr[0] = {
            .type = ConnectionAddrType::CONNECTION_ADDR_ETH,
            .info {
                .ip {
                    .ip = "172.0.0.1",
                    .port = 0,
                }
            }
        }
    };
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->ConvertDeviceInfoToDmDevice(deviceInfo, dmDevice);
    EXPECT_EQ(softbusListener->isRadarSoLoad_, true);
}

HWTEST_F(SoftbusListenerTest, ConvertDeviceInfoToDmDevice_003, testing::ext::TestSize.Level0)
{
    DmDeviceInfo dmDevice;
    DeviceInfo deviceInfo = {
        .devId = "deviceId",
        .devType = (DeviceType)1,
        .devName = "11111",
        .addrNum = 1,
        .addr[0] = {
            .type = ConnectionAddrType::CONNECTION_ADDR_BR,
            .info {
                .ip {
                    .ip = "172.0.0.1",
                    .port = 0,
                }
            }
        }
    };
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->ConvertDeviceInfoToDmDevice(deviceInfo, dmDevice);
    EXPECT_EQ(softbusListener->isRadarSoLoad_, true);
}

HWTEST_F(SoftbusListenerTest, ConvertDeviceInfoToDmDevice_004, testing::ext::TestSize.Level0)
{
    DmDeviceInfo dmDevice;
    DeviceInfo deviceInfo = {
        .devId = "deviceId",
        .devType = (DeviceType)1,
        .devName = "11111",
        .addrNum = 1,
        .addr[0] = {
            .type = ConnectionAddrType::CONNECTION_ADDR_MAX,
            .info {
                .ip {
                    .ip = "172.0.0.1",
                    .port = 0,
                }
            }
        }
    };
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->ConvertDeviceInfoToDmDevice(deviceInfo, dmDevice);
    EXPECT_EQ(softbusListener->isRadarSoLoad_, true);
}

HWTEST_F(SoftbusListenerTest, GetNetworkTypeByNetworkId_001, testing::ext::TestSize.Level0)
{
    char *networkId;
    int32_t networkType = -1;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->GetNetworkTypeByNetworkId(networkId, networkType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

HWTEST_F(SoftbusListenerTest, CacheDiscoveredDevice_001, testing::ext::TestSize.Level0)
{
    DeviceInfo *device;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->CacheDiscoveredDevice(device);
    EXPECT_EQ(softbusListener->isRadarSoLoad_, true);
}

HWTEST_F(SoftbusListenerTest, GetTargetInfoFromCache_001, testing::ext::TestSize.Level0)
{
    std::string deviceId = "deviceId";
    DeviceInfo deviceInfo = {
        .devId = "deviceId",
        .devType = (DeviceType)1,
        .devName = "11111",
        .addrNum = 1,
        .addr[0] = {
            .type = ConnectionAddrType::CONNECTION_ADDR_WLAN,
            .info {
                .ip {
                    .ip = "172.0.0.1",
                    .port = 0,
                }
            }
        }
    };
    PeerTargetId targetId;
    ConnectionAddrType addrType;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->CacheDiscoveredDevice(&deviceInfo);
    int32_t ret = softbusListener->GetTargetInfoFromCache(deviceId, targetId, addrType);
    EXPECT_EQ(ret, DM_OK);
}

HWTEST_F(SoftbusListenerTest, ClearDiscoveredDevice_001, testing::ext::TestSize.Level0)
{
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->ClearDiscoveredDevice();
    EXPECT_EQ(softbusListener->isRadarSoLoad_, true);
}

HWTEST_F(SoftbusListenerTest, IsDmRadarHelperReady_001, testing::ext::TestSize.Level0)
{
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    bool ret = softbusListener->IsDmRadarHelperReady();
    EXPECT_EQ(ret, true);
}

HWTEST_F(SoftbusListenerTest, CloseDmRadarHelperObj_001, testing::ext::TestSize.Level0)
{
    std::string name;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    bool ret = softbusListener->CloseDmRadarHelperObj(name);
    EXPECT_EQ(ret, true);
}

HWTEST_F(SoftbusListenerTest, OnSessionOpened_001, testing::ext::TestSize.Level0)
{
    int sessionId = 0;
    int result = 1;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    EXPECT_EQ(OnSessionOpened(sessionId, result), DM_OK);
}

HWTEST_F(SoftbusListenerTest, OnSessionClosed_001, testing::ext::TestSize.Level0)
{
    int sessionId = 0;
    OnSessionClosed(sessionId);
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    EXPECT_EQ(softbusListener->isRadarSoLoad_, false);
}

HWTEST_F(SoftbusListenerTest, OnBytesReceived_001, testing::ext::TestSize.Level0)
{
    int sessionId = 0;
    std::string str = "1234513135215123";
    OnBytesReceived(sessionId, str.c_str(), str.size());
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    EXPECT_EQ(softbusListener->isRadarSoLoad_, false);
}

HWTEST_F(SoftbusListenerTest, OnPinHolderSessionOpened_001, testing::ext::TestSize.Level0)
{
    int sessionId = 0;
    int result = 1;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    EXPECT_EQ(OnPinHolderSessionOpened(sessionId, result), ERR_DM_FAILED);
}

HWTEST_F(SoftbusListenerTest, OnPinHolderSessionClosed_001, testing::ext::TestSize.Level0)
{
    int sessionId = 0;
    OnPinHolderSessionClosed(sessionId);
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    EXPECT_EQ(softbusListener->isRadarSoLoad_, false);
}

HWTEST_F(SoftbusListenerTest, OnPinHolderBytesReceived_001, testing::ext::TestSize.Level0)
{
    int sessionId = 0;
    std::string str = "1234513135215123";
    OnPinHolderBytesReceived(sessionId, str.c_str(), str.size());
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    EXPECT_EQ(softbusListener->isRadarSoLoad_, false);
}

HWTEST_F(SoftbusListenerTest, GetTrustedDeviceList_001, testing::ext::TestSize.Level0)
{
    std::vector<DmDeviceInfo> deviceInfoList;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->GetTrustedDeviceList(deviceInfoList);
    EXPECT_EQ(ret, DM_OK);
}

HWTEST_F(SoftbusListenerTest, GetTrustedDeviceList_002, testing::ext::TestSize.Level0)
{
    std::vector<DmDeviceInfo> deviceInfoList;
    DmDeviceInfo deviceInfo;
    deviceInfoList.push_back(deviceInfo);
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->GetTrustedDeviceList(deviceInfoList);
    EXPECT_EQ(ret, DM_OK);
}

HWTEST_F(SoftbusListenerTest, GetDeviceInfo_001, testing::ext::TestSize.Level0)
{
    std::string networkId = "networkId";
    DmDeviceInfo info;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->GetDeviceInfo(networkId, info);
    EXPECT_EQ(true, checkSoftbusRes(ret));
}

HWTEST_F(SoftbusListenerTest, GetLocalDeviceInfo_001, testing::ext::TestSize.Level0)
{
    DmDeviceInfo info;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->GetLocalDeviceInfo(info);
    EXPECT_EQ(true, checkSoftbusRes(ret));
}

HWTEST_F(SoftbusListenerTest, ConvertBytesToUpperCaseHexString_001, testing::ext::TestSize.Level0)
{
    uint8_t arr[7] = {1, 2, 3, 4, 5, 6, 7};
    size_t size = 7;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    auto ret = softbusListener->ConvertBytesToUpperCaseHexString(arr, size);
    EXPECT_EQ(ret.empty(), false);
}

HWTEST_F(SoftbusListenerTest, GetDeviceSecurityLevel_001, testing::ext::TestSize.Level0)
{
    std::string networkId = "networkId";
    int32_t securityLevel = -1;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->GetDeviceSecurityLevel(networkId.c_str(), securityLevel);
    EXPECT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(SoftbusListenerTest, GetDmRadarHelperObj_001, testing::ext::TestSize.Level0)
{
    std::shared_ptr<SoftbusListener> softbusListener_ = std::make_shared<SoftbusListener>();
    auto ret = softbusListener_->GetDmRadarHelperObj();
    EXPECT_EQ(ret, nullptr);
}

HWTEST_F(SoftbusListenerTest, SetHostPkgName_001, testing::ext::TestSize.Level0)
{
    std::string hostName = "hostName";
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->SetHostPkgName(hostName);
    EXPECT_EQ(softbusListener->hostName_, hostName);
}

HWTEST_F(SoftbusListenerTest, GetHostPkgName_001, testing::ext::TestSize.Level0)
{
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    auto ret = softbusListener->GetHostPkgName();
    EXPECT_EQ(ret.empty(), false);
}

HWTEST_F(SoftbusListenerTest, CacheDeviceInfo_001, testing::ext::TestSize.Level0)
{
    std::string deviceId;
    std::shared_ptr<DeviceInfo> infoPtr = nullptr;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->CacheDeviceInfo(deviceId, infoPtr);
    EXPECT_EQ(softbusListener->isRadarSoLoad_, false);
}

HWTEST_F(SoftbusListenerTest, CacheDeviceInfo_002, testing::ext::TestSize.Level0)
{
    std::string deviceId = "deviceId";
    std::shared_ptr<DeviceInfo> infoPtr = std::make_shared<DeviceInfo>();
    infoPtr->addrNum = 0;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->CacheDeviceInfo(deviceId, infoPtr);
    EXPECT_EQ(softbusListener->isRadarSoLoad_, false);
}

HWTEST_F(SoftbusListenerTest, CacheDeviceInfo_003, testing::ext::TestSize.Level0)
{
    std::string deviceId = "deviceId";
    std::shared_ptr<DeviceInfo> infoPtr = std::make_shared<DeviceInfo>();
    infoPtr->addrNum = 1;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    softbusListener->CacheDeviceInfo(deviceId, infoPtr);
    EXPECT_EQ(softbusListener->isRadarSoLoad_, false);
}

HWTEST_F(SoftbusListenerTest, GetIPAddrTypeFromCache_001, testing::ext::TestSize.Level0)
{
    std::string deviceId = "deviceId";
    std::string ip = "10.11.12.13.14";
    ConnectionAddrType addrType;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->GetIPAddrTypeFromCache(deviceId, ip, addrType);
    EXPECT_EQ(ret, ERR_DM_BIND_INPUT_PARA_INVALID);
}

HWTEST_F(SoftbusListenerTest, GetIPAddrTypeFromCache_002, testing::ext::TestSize.Level0)
{
    std::string deviceId = "deviceId";
    std::string ip = "10.11.12.13.14";
    ConnectionAddrType addrType;
    std::vector<std::pair<ConnectionAddrType, std::shared_ptr<DeviceInfo>>> deviceVec;
    discoveredDeviceMap.insert(std::pair<std::string,
        std::vector<std::pair<ConnectionAddrType, std::shared_ptr<DeviceInfo>>>>(deviceId, deviceVec));
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->GetIPAddrTypeFromCache(deviceId, ip, addrType);
    EXPECT_EQ(ret, ERR_DM_BIND_INPUT_PARA_INVALID);
}

HWTEST_F(SoftbusListenerTest, GetIPAddrTypeFromCache_003, testing::ext::TestSize.Level0)
{
    std::string deviceId = "deviceId";
    std::string ip = "10.11.12.13.14";
    ConnectionAddrType addrType;
    std::shared_ptr<DeviceInfo> infoPtr = std::make_shared<DeviceInfo>();
    std::vector<std::pair<ConnectionAddrType, std::shared_ptr<DeviceInfo>>> deviceVec;
    deviceVec.push_back(std::pair<ConnectionAddrType, std::shared_ptr<DeviceInfo>>(addrType, infoPtr));
    discoveredDeviceMap.insert(std::pair<std::string,
        std::vector<std::pair<ConnectionAddrType, std::shared_ptr<DeviceInfo>>>>(deviceId, deviceVec));
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->GetIPAddrTypeFromCache(deviceId, ip, addrType);
    EXPECT_EQ(ret, ERR_DM_BIND_INPUT_PARA_INVALID);
}

HWTEST_F(SoftbusListenerTest, InitSoftbusListener_001, testing::ext::TestSize.Level0)
{
    SoftbusListener::GetSoftbusRefreshCb();
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->InitSoftbusListener();
    EXPECT_EQ(ret, DM_OK);
}

HWTEST_F(SoftbusListenerTest, RefreshSoftbusLNN_001, testing::ext::TestSize.Level0)
{
    std::string pkgName = "pkgName";
    DmSubscribeInfo dmSubInfo;
    std::string customData = "customData";
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    NodeStatusType type = NodeStatusType::TYPE_SCREEN_STATUS;
    NodeStatus *status = nullptr;
    softbusListener->OnDeviceScreenStatusChanged(type, status);
    NodeBasicInfo nodeBasicInfo = {
        .deviceName = {"device_001"},
        .networkId = {"network_001"},
        .deviceTypeId = 16789,
        .osType = 24,
        .osVersion = {1}
    };
    NodeStatus nodeStatus = {
        .authStatus = 0,
        .dataBaseStatus = 1,
        .meshType = 2,
        .reserved = {1},
        .basicInfo = nodeBasicInfo
    };
    status = &nodeStatus;
    softbusListener->OnDeviceScreenStatusChanged(type, status);
    type = NodeStatusType::TYPE_AUTH_STATUS;
    softbusListener->OnDeviceScreenStatusChanged(type, status);
    int32_t ret = softbusListener->RefreshSoftbusLNN(pkgName.c_str(), dmSubInfo, customData);
    EXPECT_EQ(true, checkSoftbusRes(ret));
}

HWTEST_F(SoftbusListenerTest, StopRefreshSoftbusLNN_001, testing::ext::TestSize.Level0)
{
    uint16_t subscribeId = 1345;
    if (softbusListener == nullptr) {
        softbusListener = std::make_shared<SoftbusListener>();
    }
    int32_t ret = softbusListener->StopRefreshSoftbusLNN(subscribeId);
    softbusListener->OnLocalDevInfoChange();
    std::string msg = "123";
    softbusListener->DeviceNotTrust(msg);
    NodeBasicInfo *info = nullptr;
    softbusListener->OnSoftbusDeviceOffline(info);
    TrustChangeType type = TrustChangeType::DEVICE_NOT_TRUSTED;
    const uint32_t msgLen = 100;
    char msg1[msgLen] = {0};
    softbusListener->OnDeviceTrustedChange(type, msg1, msgLen);
    char *msg2 = nullptr;
    softbusListener->OnDeviceTrustedChange(type, msg2, msgLen);
    const uint32_t msgLen2 = MAX_SOFTBUS_MSG_LEN + 1;
    softbusListener->OnDeviceTrustedChange(type, msg1, msgLen2);
    softbusListener->OnDeviceTrustedChange(type, msg2, msgLen2);
    softbusListener->SendAclChangedBroadcast(msg);
    char devicelist[msgLen] = {0};
    uint16_t deviceTypeId = 0;
    int32_t errcode = -1;
    softbusListener->OnCredentialAuthStatus(devicelist, msgLen, deviceTypeId, errcode);
    std::string deviceList2;
    deviceTypeId = 0xA2F;
    softbusListener->CredentialAuthStatusProcess(deviceList2, deviceTypeId, errcode);
    EXPECT_EQ(true, checkSoftbusRes(ret));
}
} // namespace
} // namespace DistributedHardware
} // namespace OHOS