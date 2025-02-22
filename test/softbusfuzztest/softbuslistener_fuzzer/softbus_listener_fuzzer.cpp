/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <fuzzer/FuzzedDataProvider.h>
#include "device_manager_impl.h"
#include "dm_constants.h"
#include "softbus_listener.h"
#include "dm_device_info.h"
#include "dm_publish_info.h"
#include "dm_subscribe_info.h"
#include "softbus_session.h"
#include <memory>
#include "softbus_listener_fuzzer.h"

namespace OHOS {
namespace DistributedHardware {

namespace {
    constexpr int32_t INT32NUM = 3;
    constexpr int32_t DATA_LEN = 20;
    constexpr int32_t CONNECTION_ADDR_USB = 5;
}

class ISoftbusDiscoveringCallbackTest : public ISoftbusDiscoveringCallback {
public:
    virtual ~ISoftbusDiscoveringCallbackTest()
    {
    }
    void OnDeviceFound(const std::string &pkgName, const DmDeviceInfo &info, bool isOnline) override
    {
        (void)pkgName;
        (void)info;
        (void)isOnline;
    }
    void OnDiscoveringResult(const std::string &pkgName, int32_t subscribeId, int32_t result) override
    {
        (void)pkgName;
        (void)subscribeId;
        (void)result;
    }
};

std::shared_ptr<SoftbusListener> softbusListener_ =  std::make_shared<SoftbusListener>();

void SoftBusListenerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t) + sizeof(uint32_t) + sizeof(uint16_t))) {
        return;
    }
    std::string displayName(reinterpret_cast<const char*>(data), size);
    softbusListener_->SetLocalDisplayName(displayName);
    softbusListener_->DeleteCacheDeviceInfo();
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string ip(reinterpret_cast<const char*>(data), size);
    ConnectionAddrType addrType = ConnectionAddrType::CONNECTION_ADDR_ETH;
    std::shared_ptr<DeviceInfo> infoPtr = std::make_shared<DeviceInfo>();
    softbusListener_->GetIPAddrTypeFromCache(deviceId, ip, addrType);
    DmDeviceInfo deviceInfo;
    softbusListener_->DeviceOnLine(deviceInfo);
    softbusListener_->DeviceOffLine(deviceInfo);
    softbusListener_->DeviceNameChange(deviceInfo);
    std::string strMsg(reinterpret_cast<const char*>(data), size);
    softbusListener_->DeviceNotTrust(strMsg);
    softbusListener_->DeviceTrustedChange(strMsg);
    softbusListener_->DeviceUserIdCheckSumChange(strMsg);
    softbusListener_->DeviceScreenStatusChange(deviceInfo);
    std::string deviceList(reinterpret_cast<const char*>(data), size);
    FuzzedDataProvider fdp(data, size);
    int32_t errcode = fdp.ConsumeIntegral<int32_t>();
    uint16_t deviceTypeId = fdp.ConsumeIntegral<uint16_t>();
    softbusListener_->CredentialAuthStatusProcess(deviceList, deviceTypeId, errcode);
    uint32_t deviceListLen = fdp.ConsumeIntegral<uint32_t>();
    softbusListener_->OnCredentialAuthStatus(deviceList.data(), deviceListLen, deviceTypeId, errcode);
    NodeStatusType type = NodeStatusType::TYPE_SCREEN_STATUS;
    NodeStatus *status = nullptr;
    softbusListener_->OnDeviceScreenStatusChanged(type, status);
    NodeBasicInfo nodeBasicInfo = {
        .networkId = {"networkId"},
        .deviceName = {"deviceNameInfo"},
        .deviceTypeId = 1,
        .osType = 1,
        .osVersion = {1}
    };
    NodeStatus nodeStatus = {
        .basicInfo = nodeBasicInfo,
        .authStatus = 1,
        .dataBaseStatus = 1,
        .meshType = 1,
        .reserved = {1}
    };
    softbusListener_->OnDeviceScreenStatusChanged(type, status);
    type = NodeStatusType::TYPE_AUTH_STATUS;
    softbusListener_->OnDeviceScreenStatusChanged(type, status);
    softbusListener_->OnSoftbusDeviceOnline(&nodeBasicInfo);
}

void SoftBusListenerFirstFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    NodeBasicInfo nodeBasicInfo = {
        .networkId = {"networkId"},
        .deviceName = {"deviceNameInfo"},
        .deviceTypeId = 1,
        .osType = 1,
        .osVersion = {1}
    };
    NodeBasicInfoType typeInfo = NodeBasicInfoType::TYPE_DEVICE_NAME;
    softbusListener_->OnSoftbusDeviceOffline(typeInfo, &nodeBasicInfo);
    softbusListener_->OnSoftbusDeviceInfoChanged(typeInfo, &nodeBasicInfo);
    typeInfo = NodeBasicInfoType::TYPE_NETWORK_INFO;
    softbusListener_->OnSoftbusDeviceOffline(typeInfo, &nodeBasicInfo);
    softbusListener_->OnSoftbusDeviceInfoChanged(typeInfo, &nodeBasicInfo);
    softbusListener_->OnLocalDevInfoChange();
    TrustChangeType changeType = TrustChangeType::DEVICE_NOT_TRUSTED;
    std::string strMsg(reinterpret_cast<const char*>(data), size);
    uint32_t msgLen = static_cast<uint32_t>(strMsg.length());
    softbusListener_->OnDeviceTrustedChange(changeType, strMsg.data(), msgLen);
    changeType = TrustChangeType::DEVICE_TRUST_RELATIONSHIP_CHANGE;
    softbusListener_->OnDeviceTrustedChange(changeType, strMsg.data(), msgLen);
    changeType = TrustChangeType::DEVICE_FOREGROUND_USERID_CHANGE;
    softbusListener_->OnDeviceTrustedChange(changeType, strMsg.data(), msgLen);
    DeviceInfo *device = nullptr;
    softbusListener_->OnSoftbusDeviceFound(device);
    DeviceInfo deviceInfo;
    softbusListener_->OnSoftbusDeviceFound(&deviceInfo);
    FuzzedDataProvider fdp(data, size);
    int32_t publishId = fdp.ConsumeIntegral<int32_t>();
    softbusListener_->StopPublishSoftbusLNN(publishId);
    std::string pkgName(reinterpret_cast<const char*>(data), size);
    std::shared_ptr<ISoftbusDiscoveringCallback> callback = nullptr;
    softbusListener_->RegisterSoftbusLnnOpsCbk(pkgName, callback);
    callback = std::make_shared<ISoftbusDiscoveringCallbackTest>();
    softbusListener_->RegisterSoftbusLnnOpsCbk(pkgName, callback);
    softbusListener_->UnRegisterSoftbusLnnOpsCbk(pkgName);
    std::string networkId(reinterpret_cast<const char*>(data), size);
    DmDeviceInfo dmInfo;
    softbusListener_->GetDeviceInfo(dmInfo);
    softbusListener_->GetLocalDeviceInfo(dmInfo);
    std::string udid(reinterpret_cast<const char*>(data), size);
    softbusListener_->GetNetworkIdByUdid(udid, networkId);
    bool isWakeUp = false;
    std::string callerId(reinterpret_cast<const char*>(data), size);
    softbusListener_->ShiftLNNGear(isWakeUp, callerId);
    softbusListener_->ShiftLNNGear(isWakeUp, "");
}

void SoftBusListenerSecondFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t) * INT32NUM)) {
        return;
    }
    NodeBasicInfo nodeBasicInfo = {
        .networkId = {"networkId"},
        .deviceName = {"deviceNameInfo"},
        .deviceTypeId = 1,
        .osType = 1,
        .osVersion = {1}
    };
    NodeBasicInfoType typeInfo = NodeBasicInfoType::TYPE_DEVICE_NAME;
    
    softbusListener_->OnSoftbusDeviceFound(&deviceInfo);
    FuzzedDataProvider fdp(data, size);
    int32_t devScreenStatus = fdp.ConsumeIntegral<int32_t>();
    DmDeviceInfo devInfo;
    softbusListener_->ConvertScreenStatusToDmDevice(nodeBasicInfo, devScreenStatus, devInfo);
    softbusListener_->ConvertNodeBasicInfoToDmDevice(nodeBasicInfo, devInfo);
    DmDeviceBasicInfo dmdevInfo;
    softbusListener_->ConvertNodeBasicInfoToDmDevice(nodeBasicInfo, dmdevInfo);
    uint8_t arr[DATA_LEN] = {1};
    size_t len = static_cast<size_t>(DATA_LEN);
    softbusListener_->ConvertBytesToUpperCaseHexString(arr, len);
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
    softbusListener_->ConvertDeviceInfoToDmDevice(deviceInfo, devInfo);
    int32_t networkType = fdp.ConsumeIntegral<int32_t>();
    std::string networkId(reinterpret_cast<const char*>(data), size);
    softbusListener_->GetNetworkTypeByNetworkId(networkId.data(), networkType);
    int32_t securityLevel = fdp.ConsumeIntegral<int32_t>();
    softbusListener_->GetDeviceSecurityLevel(networkId.data(), securityLevel)
    softbusListener_->CacheDiscoveredDevice(&deviceInfo);
    softbusListener_->GetDeviceScreenStatus(networkId.data(), securityLevel);
}

void SoftBusListenerThirdFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    ConnectionAddr addrInfo = {
        .type = ConnectionAddrType::CONNECTION_ADDR_ETH,
        .info {
            .br {
                .brMac = "1.0.0.1"
            },
            .ble {
                .protocol = BleProtocolType::BLE_GATT,
                .bleMac = "4.0.0.2",
                .udidHash = {1},
                .psm = 1
            },
            .ip {
                .ip = "172.0.0.2",
                .port = 1,
                .udidHash = {1}
            },
            .session {
                .sessionId = 1,
                .channelId = 1,
                .type = 1
            },
        },
        .peerUid = "peerUid"
    };
    nlohmann::json jsonObj;
    softbusListener_->ParseConnAddrInfo(&addrInfo, jsonObj);
    addrInfo.type = ConnectionAddrType::CONNECTION_ADDR_WLAN;
    softbusListener_->ParseConnAddrInfo(&addrInfo, jsonObj);
    addrInfo.type = ConnectionAddrType::CONNECTION_ADDR_BR;
    softbusListener_->ParseConnAddrInfo(&addrInfo, jsonObj);
    addrInfo.type = ConnectionAddrType::CONNECTION_ADDR_BLE;
    softbusListener_->ParseConnAddrInfo(&addrInfo, jsonObj);
    addrInfo.type = static_cast<ConnectionAddrType>(CONNECTION_ADDR_USB);
    softbusListener_->ParseConnAddrInfo(&addrInfo, jsonObj);
    std::string remoteUdid(reinterpret_cast<const char*>(data), size);
    std::vector<uint32_t> userIds;
    softbusListener_->SetForegroundUserIdsToDSoftBus(remoteUdid, userIds);
    DistributedDeviceProfile::AccessControlProfile profile;
    DmDeviceInfo deviceInfo;
    softbusListener_->ConvertAclToDeviceInfo(profile, deviceInfo);
    std::string pkgName(reinterpret_cast<const char*>(data), size);
    std::string extra(reinterpret_cast<const char*>(data), size);
    std::vector<DmDeviceInfo> deviceList;
    softbusListener_->GetAllTrustedDeviceList(pkgName, extra, deviceList);
}

void SoftBusListenerThirdFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    std::string udidHash(reinterpret_cast<const char*>(data), size);
    std::string udid(reinterpret_cast<const char*>(data), size);
    softbusListener_->GetUdidFromDp(udidHash, udid);
    NodeBasicInfo nodeBasicInfo = {
        .networkId = {"networkId"},
        .deviceName = {"deviceNameInfo"},
        .deviceTypeId = 1,
        .osType = 1,
        .osVersion = {1}
    };
    softbusListener_->OnSoftbusDeviceOffline(&nodeBasicInfo);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::SoftBusListenerFuzzTest(data, size);
    OHOS::DistributedHardware::SoftBusListenerFirstFuzzTest(data, size);
    OHOS::DistributedHardware::SoftBusListenerSecondFuzzTest(data, size);
    OHOS::DistributedHardware::SoftBusListenerThirdFuzzTest(data, size);

    return 0;
}
