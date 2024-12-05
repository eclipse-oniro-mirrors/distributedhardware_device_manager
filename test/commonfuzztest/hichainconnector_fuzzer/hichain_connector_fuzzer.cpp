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
#include <utility>
#include <vector>

#include "device_manager_service_listener.h"
#include "dm_auth_manager.h"
#include "hichain_connector.h"

#include "hichain_connector_fuzzer.h"

namespace OHOS {
namespace DistributedHardware {

class HiChainConnectorCallbackTest : public IHiChainConnectorCallback {
public:
    HiChainConnectorCallbackTest() {}
    virtual ~HiChainConnectorCallbackTest() {}
    void OnGroupCreated(int64_t requestId, const std::string &groupId) override
    {
        (void)requestId;
        (void)groupId;
    }
    void OnMemberJoin(int64_t requestId, int32_t status) override
    {
        (void)requestId;
        (void)status;
    }
    std::string GetConnectAddr(std::string deviceId) override
    {
        (void)deviceId;
        return "";
    }
    int32_t GetPinCode(int32_t &code) override
    {
        (void)code;
        return DM_OK;
    }
};

void AddGroupInfo(std::vector<GroupInfo> &groupList)
{
    GroupInfo groupInfo1;
    groupInfo1.groupId = "234";
    groupInfo1.groupType = GROUP_TYPE_IDENTICAL_ACCOUNT_GROUP;
    groupList.push_back(groupInfo1);
    GroupInfo groupInfo2;
    groupInfo2.groupId = "1485";
    groupInfo2.groupOwner = DM_PKG_NAME;
    groupList.push_back(groupInfo2);
}

void AddAclInfo(std::vector<std::pair<int32_t, std::string>> &delACLInfoVec, std::vector<int32_t> &userIdVec)
{
    int32_t key = 12;
    std::string value = "acl_info1";
    delACLInfoVec.push_back(std::make_pair(key, value));
    userIdVec.push_back(key);
    int32_t key1 = 23;
    value = "acl_info2";
    delACLInfoVec.push_back(std::make_pair(key1, value));
    userIdVec.push_back(key);
    int32_t key2 = 25;
    value = "acl_info3";
    delACLInfoVec.push_back(std::make_pair(key2, value));
    userIdVec.push_back(key);
}

void HiChainConnectorFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::shared_ptr<HiChainConnector> hichainConnector = std::make_shared<HiChainConnector>();
    hichainConnector->RegisterHiChainCallback(std::make_shared<HiChainConnectorCallbackTest>());

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
    hichainConnector->GetRelatedGroupsCommon(deviceId, pkgNameStr.data(), groupList);
    hichainConnector->UnRegisterHiChainCallback();
}

void HiChainConnectorSecondFuzzTest(const uint8_t* data, size_t size)
{
    std::shared_ptr<HiChainConnector> hichainConnector = std::make_shared<HiChainConnector>();
    hichainConnector->RegisterHiChainCallback(std::make_shared<HiChainConnectorCallbackTest>());

    std::vector<GroupInfo> groupList;
    nlohmann::json jsonDeviceList;
    GroupInfo groupInfo;
    std::vector<std::string> syncGroupList;
    hichainConnector->GetSyncGroupList(groupList, syncGroupList);
    hichainConnector->IsGroupInfoInvalid(groupInfo);
    hichainConnector->UnRegisterHiChainGroupCallback();
    hichainConnector->GetJsonStr(jsonDeviceList, "key");
}

void HiChainConnectorThirdFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int64_t))) {
        return;
    }
    std::shared_ptr<HiChainConnector> hichainConnector = std::make_shared<HiChainConnector>();
    hichainConnector->RegisterHiChainCallback(std::make_shared<HiChainConnectorCallbackTest>());
    int64_t requestId = *(reinterpret_cast<const int64_t*>(data));
    std::string groupName = "groupName";
    GroupInfo groupInfo;
    std::string userId(reinterpret_cast<const char*>(data), size);
    int32_t authType = *(reinterpret_cast<const int32_t*>(data));
    std::vector<GroupInfo> groupList;
    std::string queryParams(reinterpret_cast<const char*>(data), size);
    std::string pkgName(reinterpret_cast<const char*>(data), size);
    std::string groupId(reinterpret_cast<const char*>(data), size);
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string reqDeviceId(reinterpret_cast<const char*>(data), size);
    nlohmann::json jsonOutObj;
    std::shared_ptr<IDmGroupResCallback> callback;
    std::string jsonStr(reinterpret_cast<const char*>(data), size);
    int32_t groupType = *(reinterpret_cast<const int32_t*>(data));
    int32_t switchUserId = *(reinterpret_cast<const int32_t*>(data));
    std::string reqParams(reinterpret_cast<const char*>(data), size);
    std::string credentialInfo(reinterpret_cast<const char*>(data), size);
    int operationCode = GroupOperationCode::MEMBER_JOIN;
    hichainConnector->deviceGroupManager_ = nullptr;
    hichainConnector->AddMember(deviceId, queryParams);
    hichainConnector->getRegisterInfo(queryParams, jsonStr);
    hichainConnector->addMultiMembers(groupType, userId, jsonOutObj);
    hichainConnector->addMultiMembersExt(credentialInfo);
    hichainConnector->deleteMultiMembers(groupType, userId, jsonOutObj);
    hichainConnector->GetGroupInfoCommon(authType, queryParams, pkgName.c_str(), groupList);
    hichainConnector->hiChainConnectorCallback_ = nullptr;
    hichainConnector->GetConnectPara(deviceId, reqDeviceId);
    hichainConnector->onRequest(requestId, operationCode, reqParams.c_str());
    hichainConnector->RegisterHiChainCallback(std::make_shared<HiChainConnectorCallbackTest>());
    if (hichainConnector->deviceGroupManager_ == nullptr) {
        hichainConnector->deviceGroupManager_ = GetGmInstance();
    }
    hichainConnector->IsGroupCreated(groupName, groupInfo);
    hichainConnector->GetGroupInfoExt(authType, queryParams, groupList);
    hichainConnector->GetGroupInfoCommon(authType, queryParams, pkgName.c_str(), groupList);
    hichainConnector->RegisterHiChainGroupCallback(callback);
    hichainConnector->GetJsonInt(jsonOutObj, "key");
    hichainConnector->deleteMultiMembers(groupType, userId, jsonOutObj);
    hichainConnector->DeleteAllGroupByUdid(reqParams);
}

void HiChainConnectorForthFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int64_t))) {
        return;
    }

    std::shared_ptr<HiChainConnector> hichainConnector = std::make_shared<HiChainConnector>();
    hichainConnector->RegisterHiChainCallback(std::make_shared<HiChainConnectorCallbackTest>());

    int64_t requestId = *(reinterpret_cast<const int64_t*>(data));
    std::string groupName(reinterpret_cast<const char*>(data), size);
    std::string groupId = "groupId_forth";
    std::string deviceId = "deviceId_forth";
    std::string returnData(reinterpret_cast<const char*>(data), size);
    std::string userId = "userId_forth";
    int32_t authType = *(reinterpret_cast<const int32_t*>(data));
    int operationCode = GroupOperationCode::MEMBER_JOIN;
    int errCode = 102;
    std::vector<std::string> syncGroupList;
    std::vector<std::pair<int32_t, std::string>> delACLInfoVec;
    std::vector<int32_t> userIdVec;
    hichainConnector->DeleteGroupByACL(delACLInfoVec, userIdVec);
    std::vector<GroupInfo> groupList;
    AddGroupInfo(groupList);
    AddAclInfo(delACLInfoVec, userIdVec);
    hichainConnector->DeleteGroup(groupId);
    hichainConnector->DeleteGroupExt(groupId);
    hichainConnector->DeleteGroup(authType, groupId);
    hichainConnector->DeleteGroup(requestId, userId, authType);
    hichainConnector->DelMemberFromGroup(groupId, deviceId);
    hichainConnector->DeleteRedundanceGroup(userId);
    hichainConnector->DealRedundanceGroup(userId, authType);
    hichainConnector->DeleteGroupByACL(delACLInfoVec, userIdVec);
    hichainConnector->IsNeedDelete(groupName, authType, delACLInfoVec);
    hichainConnector->onFinish(requestId, operationCode, returnData.c_str());
    hichainConnector->onError(requestId, operationCode, errCode, returnData.c_str());
    hichainConnector->onRequest(requestId, operationCode, returnData.c_str());
    operationCode = GroupOperationCode::GROUP_CREATE;
    hichainConnector->onFinish(requestId, operationCode, returnData.c_str());
    hichainConnector->onError(requestId, operationCode, errCode, returnData.c_str());
    operationCode == GroupOperationCode::MEMBER_DELETE;
    hichainConnector->onFinish(requestId, operationCode, returnData.c_str());
    hichainConnector->onError(requestId, operationCode, errCode, returnData.c_str());
    operationCode == GroupOperationCode::GROUP_DISBAND;
    hichainConnector->onFinish(requestId, operationCode, returnData.c_str());
    hichainConnector->onError(requestId, operationCode, errCode, returnData.c_str());
    hichainConnector->GenRequestId();
    hichainConnector->GetRelatedGroups(deviceId, groupList);
    hichainConnector->GetRelatedGroupsExt(deviceId, groupList);
    hichainConnector->GetSyncGroupList(groupList, syncGroupList);
    hichainConnector->GetGroupId(userId, authType, userId);
}

void HiChainConnectorFifthFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int64_t))) {
        return;
    }

    std::shared_ptr<HiChainConnector> hichainConnector = std::make_shared<HiChainConnector>();
    hichainConnector->RegisterHiChainCallback(std::make_shared<HiChainConnectorCallbackTest>());
    int64_t requestId = *(reinterpret_cast<const int64_t*>(data));
    std::string groupName = "groupName_fifth";
    int32_t authType = *(reinterpret_cast<const int32_t*>(data));
    std::string params = "params";
    int32_t osAccountUserId = *(reinterpret_cast<const int32_t*>(data));
    nlohmann::json jsonDeviceList;
    std::vector<std::pair<int32_t, std::string>> delACLInfoVec;
    std::vector<int32_t> userIdVec;
    std::vector<std::pair<int32_t, std::string>> delAclInfoVec1;
    std::string jsonStr = R"({"content": {"deviceid": "123"}}, authId: "123456"))";
    std::vector<std::string> udidList;
    int32_t key = 12;
    std::string value = "acl_info1";
    std::string credentialInfo = R"({"content": {"deviceid": "123"}}, authId: "123456"))";
    std::string groupOwner(reinterpret_cast<const char*>(data), size);
    delAclInfoVec1.push_back(std::make_pair(key, value));
    nlohmann::json jsonObj;
    jsonObj[AUTH_TYPE] = 1;
    jsonObj[FIELD_USER_ID] = "123456";
    jsonObj[FIELD_CREDENTIAL_TYPE] = 1;
    jsonObj[FIELD_OPERATION_CODE] = 1;
    jsonObj[FIELD_TYPE] = "filed_type";
    jsonObj[FIELD_DEVICE_LIST] = "device_list";
    hichainConnector->deviceGroupManager_ = nullptr;
    hichainConnector->CreateGroup(requestId, groupName);
    hichainConnector->CreateGroup(requestId, authType, groupName, jsonDeviceList);
    if (hichainConnector->deviceGroupManager_ == nullptr) {
        hichainConnector->deviceGroupManager_ = GetGmInstance();
    }
    hichainConnector->CreateGroup(requestId, groupName);
    hichainConnector->CreateGroup(requestId, authType, groupName, jsonDeviceList);
    hichainConnector->ParseRemoteCredential(authType, groupName, jsonDeviceList, params, osAccountUserId);
    hichainConnector->ParseRemoteCredential(authType, "", jsonDeviceList, params, osAccountUserId);
    hichainConnector->IsNeedDelete(groupName, authType, delACLInfoVec);
    hichainConnector->DeleteGroupByACL(delAclInfoVec1, userIdVec);
    hichainConnector->GetTrustedDevicesUdid(jsonStr.data(), udidList);
    jsonStr = R"({"content": {"deviceid": "123"}}, authId: "123456")";
    hichainConnector->GetTrustedDevicesUdid(jsonStr.data(), udidList);
    jsonStr = R"({"content": {"deviceid": "123"}}, localId: "123456")";
    hichainConnector->GetTrustedDevicesUdid(jsonStr.data(), udidList);
}

void HiChainConnectorSixthFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::shared_ptr<HiChainConnector> hichainConnector = std::make_shared<HiChainConnector>();
    hichainConnector->RegisterHiChainCallback(std::make_shared<HiChainConnectorCallbackTest>());
    std::string groupOwner(reinterpret_cast<const char*>(data), size);
    nlohmann::json jsonObj;
    std::string deviceId = "deviceId";
    std::string key = "localDeviceId";
    jsonObj["deviceId"] = 1;
    hichainConnector->GetJsonInt(jsonObj, key);
    hichainConnector->GetJsonInt(jsonObj, key);
    jsonObj[key] = 1;
    jsonObj["deviceName"] = "devieName1";
    hichainConnector->GetJsonInt(jsonObj, "devieName");
    hichainConnector->AddMember(deviceId, SafeDump(jsonObj));
    jsonObj[TAG_DEVICE_ID] = "deviceId_001";
    jsonObj[PIN_CODE_KEY] = 1;
    jsonObj[TAG_GROUP_ID] = "groupId";
    jsonObj[TAG_REQUEST_ID] = 1;
    jsonObj[TAG_GROUP_NAME] = "groupName";
    hichainConnector->AddMember(deviceId, SafeDump(jsonObj));

    nlohmann::json jsonObjCre;
    std::string params;
    jsonObjCre[AUTH_TYPE] = 1;
    jsonObjCre["userId"] = "user_001";
    jsonObjCre[FIELD_CREDENTIAL_TYPE] = 1;
    jsonObjCre[FIELD_OPERATION_CODE] = 1;
    jsonObjCre[FIELD_META_NODE_TYPE] = "metaNode_002";
    jsonObjCre[FIELD_DEVICE_LIST] = "deviceList";
    std::string credentialInfo = SafeDump(jsonObjCre);
    hichainConnector->ParseRemoteCredentialExt(credentialInfo, params, groupOwner);
    int32_t groupType = *(reinterpret_cast<const int32_t*>(data));
    nlohmann::json jsonDeviceList;
    int32_t osAccountUserId = 0;
    std::string userId = "user_002";
    jsonDeviceList[FIELD_DEVICE_LIST] = "deviceList";
    hichainConnector->ParseRemoteCredential(groupType, userId, jsonDeviceList, params, osAccountUserId);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::HiChainConnectorFuzzTest(data, size);
    OHOS::DistributedHardware::HiChainConnectorSecondFuzzTest(data, size);
    OHOS::DistributedHardware::HiChainConnectorThirdFuzzTest(data, size);
    OHOS::DistributedHardware::HiChainConnectorForthFuzzTest(data, size);
    OHOS::DistributedHardware::HiChainConnectorFifthFuzzTest(data, size);
    OHOS::DistributedHardware::HiChainConnectorSixthFuzzTest(data, size);
    return 0;
}