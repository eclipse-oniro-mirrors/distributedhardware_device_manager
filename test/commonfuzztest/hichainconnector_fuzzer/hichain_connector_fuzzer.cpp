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

#include <string>
#include <cstdlib>
#include <random>
#include <vector>

#define private public
#include "device_manager_service_listener.h"
#include "dm_auth_manager.h"
#include "hichain_connector.h"
#undef private

#include "hichain_connector_fuzzer.h"

namespace OHOS {
namespace DistributedHardware {
void HiChainConnectorFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::shared_ptr<SoftbusConnector> softbusConnector = std::make_shared<SoftbusConnector>();
    std::shared_ptr<DeviceManagerServiceListener> listener = std::make_shared<DeviceManagerServiceListener>();
    std::shared_ptr<HiChainConnector> hiChainConnector = std::make_shared<HiChainConnector>();
    std::shared_ptr<HiChainAuthConnector> hiChainAuthConnector = std::make_shared<HiChainAuthConnector>();
    std::shared_ptr<DmAuthManager> authMgr =
        std::make_shared<DmAuthManager>(softbusConnector, hiChainConnector, listener, hiChainAuthConnector);

    std::shared_ptr<HiChainConnector> hichainConnector = std::make_shared<HiChainConnector>();
    hichainConnector->RegisterHiChainCallback(std::shared_ptr<IHiChainConnectorCallback>(authMgr));

    std::string userId(reinterpret_cast<const char*>(data), size);
    int32_t authType = *(reinterpret_cast<const int32_t*>(data));
    std::vector<GroupInfo> groupList;
    std::string queryParams(reinterpret_cast<const char*>(data), size);
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string reqDeviceId(reinterpret_cast<const char*>(data), size);
    std::string hostDevice(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> remoteGroupIdList;
    int32_t groupType = *(reinterpret_cast<const int32_t*>(data));
    nlohmann::json jsonDeviceList;
    std::string groupOwner(reinterpret_cast<const char*>(data), size);
    std::string credentialInfo(reinterpret_cast<const char*>(data), size);
    std::string jsonStr(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> udidList;
    std::string pkgNameStr(reinterpret_cast<const char*>(data), size);
    int32_t delUserid = *(reinterpret_cast<const int32_t*>(data));

    hichainConnector->IsRedundanceGroup(userId, authType, groupList);
    hichainConnector->GetGroupInfo(queryParams, groupList);
    hichainConnector->GetGroupInfo(delUserid, queryParams, groupList);
    hichainConnector->GetGroupType(deviceId);
    hichainConnector->AddMember(deviceId, queryParams);
    hichainConnector->GetConnectPara(deviceId, reqDeviceId);
    hichainConnector->IsDevicesInP2PGroup(hostDevice, reqDeviceId);
    hichainConnector->SyncGroups(deviceId, remoteGroupIdList);
    hichainConnector->DeleteTimeOutGroup(deviceId.data());
    hichainConnector->getRegisterInfo(queryParams, jsonStr);
    hichainConnector->GetGroupId(userId, groupType, queryParams);
    hichainConnector->addMultiMembers(groupType, userId, jsonDeviceList);
    hichainConnector->GetGroupIdExt(userId, groupType, queryParams, groupOwner);
    hichainConnector->ParseRemoteCredentialExt(credentialInfo, queryParams, groupOwner);
    hichainConnector->addMultiMembersExt(credentialInfo);
    hichainConnector->GetTrustedDevices(deviceId);
    hichainConnector->GetTrustedDevicesUdid(jsonStr.data(), udidList);
    hichainConnector->DeleteAllGroup(delUserid);
    hichainConnector->DeleteP2PGroup(delUserid);
    hichainConnector->GetRelatedGroupsCommon(deviceId, pkgNameStr.data(), groupList);
    hichainConnector->UnRegisterHiChainCallback();
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::HiChainConnectorFuzzTest(data, size);

    return 0;
}