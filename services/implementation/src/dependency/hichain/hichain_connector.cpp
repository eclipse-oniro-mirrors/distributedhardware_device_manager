/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "hichain_connector.h"

#include <cstdlib>
#include <ctime>
#include <functional>
#include <securec.h>

#include "dm_anonymous.h"
#include "dm_constants.h"
#include "dm_dfx_constants.h"
#include "dm_hisysevent.h"
#include "dm_log.h"
#include "dm_random.h"
#include "dm_radar_helper.h"
#include "hichain_connector_callback.h"
#include "multiple_user_connector.h"
#include "nlohmann/json.hpp"
#include "parameter.h"
#include "unistd.h"

namespace OHOS {
namespace DistributedHardware {
const int32_t PIN_CODE_NETWORK = 0;
const int32_t CREDENTIAL_NETWORK = 1;
const int32_t DELAY_TIME_MS = 10000; // 10ms
const int32_t FIELD_EXPIRE_TIME_VALUE = 7;
const int32_t SAME_ACCOUNT = 1;

constexpr const char* DEVICE_ID = "DEVICE_ID";
constexpr const char* FIELD_CREDENTIAL = "credential";
constexpr const char* ADD_HICHAIN_GROUP_SUCCESS = "ADD_HICHAIN_GROUP_SUCCESS";
constexpr const char* ADD_HICHAIN_GROUP_FAILED = "ADD_HICHAIN_GROUP_FAILED";
constexpr const char* DM_CREATE_GROUP_SUCCESS = "DM_CREATE_GROUP_SUCCESS";
constexpr const char* DM_CREATE_GROUP_FAILED = "DM_CREATE_GROUP_FAILED";
constexpr const char* ADD_HICHAIN_GROUP_SUCCESS_MSG = "dm add member to group success.";
constexpr const char* ADD_HICHAIN_GROUP_FAILED_MSG = "dm add member to group failed.";
constexpr const char* DM_CREATE_GROUP_SUCCESS_MSG = "dm create group success.";
constexpr const char* DM_CREATE_GROUP_FAILED_MSG = "dm create group failed.";
constexpr const char* DM_PKG_NAME_EXT = "com.huawei.devicemanager";
void from_json(const nlohmann::json &jsonObject, GroupInfo &groupInfo)
{
    if (jsonObject.find(FIELD_GROUP_NAME) != jsonObject.end() && jsonObject.at(FIELD_GROUP_NAME).is_string()) {
        groupInfo.groupName = jsonObject.at(FIELD_GROUP_NAME).get<std::string>();
    }

    if (jsonObject.find(FIELD_GROUP_ID) != jsonObject.end() && jsonObject.at(FIELD_GROUP_ID).is_string()) {
        groupInfo.groupId = jsonObject.at(FIELD_GROUP_ID).get<std::string>();
    }

    if (jsonObject.find(FIELD_GROUP_OWNER) != jsonObject.end() && jsonObject.at(FIELD_GROUP_OWNER).is_string()) {
        groupInfo.groupOwner = jsonObject.at(FIELD_GROUP_OWNER).get<std::string>();
    }

    if (jsonObject.find(FIELD_GROUP_TYPE) != jsonObject.end() && jsonObject.at(FIELD_GROUP_TYPE).is_number_integer()) {
        groupInfo.groupType = jsonObject.at(FIELD_GROUP_TYPE).get<int32_t>();
    }

    if (jsonObject.find(FIELD_GROUP_VISIBILITY) != jsonObject.end() &&
        jsonObject.at(FIELD_GROUP_VISIBILITY).is_number_integer()) {
        groupInfo.groupVisibility = jsonObject.at(FIELD_GROUP_VISIBILITY).get<int32_t>();
    }

    if (jsonObject.find(FIELD_USER_ID) != jsonObject.end() && jsonObject.at(FIELD_USER_ID).is_string()) {
        groupInfo.userId = jsonObject.at(FIELD_USER_ID).get<std::string>();
    }
}

std::shared_ptr<IHiChainConnectorCallback> HiChainConnector::hiChainConnectorCallback_ = nullptr;
std::shared_ptr<IDmGroupResCallback> HiChainConnector::hiChainResCallback_ = nullptr;
int32_t HiChainConnector::networkStyle_ = PIN_CODE_NETWORK;
bool g_createGroupFlag = false;
bool g_deleteGroupFlag = false;
bool g_groupIsRedundance = false;

HiChainConnector::HiChainConnector()
{
    LOGI("HiChainConnector::constructor");
    deviceAuthCallback_ = {.onTransmit = nullptr,
                           .onSessionKeyReturned = nullptr,
                           .onFinish = HiChainConnector::onFinish,
                           .onError = HiChainConnector::onError,
                           .onRequest = HiChainConnector::onRequest};
    InitDeviceAuthService();
    deviceGroupManager_ = GetGmInstance();
    if (deviceGroupManager_ == nullptr) {
        LOGE("[HICHAIN]failed to init group manager.");
        return;
    }
    int32_t ret = deviceGroupManager_->regCallback(DM_PKG_NAME, &deviceAuthCallback_);
    if (ret != HC_SUCCESS) {
        LOGE("[HICHAIN]fail to register callback to hachain with ret:%{public}d.", ret);
        return;
    }
    LOGI("HiChainConnector::constructor success.");
}

HiChainConnector::~HiChainConnector()
{
    LOGI("HiChainConnector::destructor.");
}

int32_t HiChainConnector::RegisterHiChainCallback(std::shared_ptr<IHiChainConnectorCallback> callback)
{
    hiChainConnectorCallback_ = callback;
    return DM_OK;
}

int32_t HiChainConnector::UnRegisterHiChainCallback()
{
    hiChainConnectorCallback_ = nullptr;
    return DM_OK;
}

int32_t HiChainConnector::CreateGroup(int64_t requestId, const std::string &groupName)
{
    if (deviceGroupManager_ == nullptr) {
        LOGE("HiChainConnector::CreateGroup group manager is null, requestId %{public}" PRId64, requestId);
        return ERR_DM_INPUT_PARA_INVALID;
    }
    networkStyle_ = PIN_CODE_NETWORK;
    GroupInfo groupInfo;
    if (IsGroupCreated(groupName, groupInfo)) {
        DeleteGroup(groupInfo.groupId);
    }
    LOGI("HiChainConnector::CreateGroup requestId %{public}" PRId64, requestId);
    char localDeviceId[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localDeviceId, DEVICE_UUID_LENGTH);
    std::string sLocalDeviceId = localDeviceId;
    nlohmann::json jsonObj;
    jsonObj[FIELD_GROUP_TYPE] = GROUP_TYPE_PEER_TO_PEER_GROUP;
    jsonObj[FIELD_DEVICE_ID] = sLocalDeviceId;
    jsonObj[FIELD_GROUP_NAME] = groupName;
    jsonObj[FIELD_USER_TYPE] = 0;
    jsonObj[FIELD_GROUP_VISIBILITY] = GROUP_VISIBILITY_PUBLIC;
    jsonObj[FIELD_EXPIRE_TIME] = FIELD_EXPIRE_TIME_VALUE;
    int32_t userId = MultipleUserConnector::GetCurrentAccountUserID();
    if (userId < 0) {
        LOGE("get current process account user id failed");
        return ERR_DM_FAILED;
    }

    int32_t ret = deviceGroupManager_->createGroup(userId, requestId, DM_PKG_NAME, jsonObj.dump().c_str());
    struct RadarInfo info = {
        .funcName = "CreateGroup",
        .toCallPkg = HICHAINNAME,
        .stageRes = (ret != 0) ?
            static_cast<int32_t>(StageRes::STAGE_FAIL) : static_cast<int32_t>(StageRes::STAGE_IDLE),
        .bizState = (ret != 0) ?
            static_cast<int32_t>(BizState::BIZ_STATE_END) : static_cast<int32_t>(BizState::BIZ_STATE_START),
        .localUdid = std::string(localDeviceId),
        .errCode = ERR_DM_CREATE_GROUP_FAILED,
    };
    if (!DmRadarHelper::GetInstance().ReportAuthCreateGroup(info)) {
        LOGE("ReportAuthCreateGroup failed");
    }
    if (ret != 0) {
        LOGE("[HICHAIN]fail to create group with ret:%{public}d, requestId:%{public}" PRId64, ret, requestId);
        return ERR_DM_CREATE_GROUP_FAILED;
    }
    return DM_OK;
}

bool HiChainConnector::IsGroupCreated(std::string groupName, GroupInfo &groupInfo)
{
    nlohmann::json jsonObj;
    jsonObj[FIELD_GROUP_NAME] = groupName.c_str();
    std::string queryParams = jsonObj.dump();
    std::vector<GroupInfo> groupList;
    if (GetGroupInfo(queryParams, groupList)) {
        groupInfo = groupList[0];
        return true;
    }
    return false;
}

bool HiChainConnector::IsRedundanceGroup(const std::string &userId, int32_t authType, std::vector<GroupInfo> &groupList)
{
    nlohmann::json jsonObj;
    jsonObj[FIELD_GROUP_TYPE] = authType;
    std::string queryParams = jsonObj.dump();

    int32_t osAccountUserId = MultipleUserConnector::GetCurrentAccountUserID();
    if (osAccountUserId < 0) {
        LOGE("get current process account user id failed");
        return ERR_DM_FAILED;
    }
    if (!GetGroupInfo(osAccountUserId, queryParams, groupList)) {
        return false;
    }
    for (auto iter = groupList.begin(); iter != groupList.end(); iter++) {
        if (iter->userId != userId) {
            return true;
        }
    }
    return false;
}

bool HiChainConnector::GetGroupInfo(const std::string &queryParams, std::vector<GroupInfo> &groupList)
{
    char *groupVec = nullptr;
    uint32_t num = 0;
    int32_t userId = MultipleUserConnector::GetCurrentAccountUserID();
    if (userId < 0) {
        LOGE("get current process account user id failed");
        return false;
    }
    int32_t ret = deviceGroupManager_->getGroupInfo(userId, DM_PKG_NAME, queryParams.c_str(), &groupVec, &num);
    if (ret != 0) {
        LOGE("[HICHAIN]fail to get group info with ret:%{public}d.", ret);
        return false;
    }
    if (groupVec == nullptr) {
        LOGE("[HICHAIN]return groups info point is nullptr");
        return false;
    }
    if (num == 0) {
        LOGE("[HICHAIN]return groups info number is zero.");
        return false;
    }
    LOGI("HiChainConnector::GetGroupInfo groupNum(%{public}u)", num);
    std::string relatedGroups = std::string(groupVec);
    deviceGroupManager_->destroyInfo(&groupVec);
    nlohmann::json jsonObject = nlohmann::json::parse(relatedGroups, nullptr, false);
    if (jsonObject.is_discarded()) {
        LOGE("returnGroups parse error");
        return false;
    }
    if (!jsonObject.is_array()) {
        LOGE("json string is not array.");
        return false;
    }
    std::vector<GroupInfo> groupInfos = jsonObject.get<std::vector<GroupInfo>>();
    if (groupInfos.size() == 0) {
        LOGE("HiChainConnector::GetGroupInfo group failed, groupInfos is empty.");
        return false;
    }
    groupList = groupInfos;
    return true;
}

int32_t HiChainConnector::GetGroupInfo(const int32_t userId, const std::string &queryParams,
    std::vector<GroupInfo> &groupList)
{
    char *groupVec = nullptr;
    uint32_t num = 0;
    int32_t ret = deviceGroupManager_->getGroupInfo(userId, DM_PKG_NAME, queryParams.c_str(), &groupVec, &num);
    if (ret != 0) {
        LOGE("[HICHAIN]fail to get group info with ret:%{public}d.", ret);
        return false;
    }
    if (groupVec == nullptr) {
        LOGE("[HICHAIN]return groups info point is nullptr");
        return false;
    }
    if (num == 0) {
        LOGE("[HICHAIN]return groups info number is zero.");
        return false;
    }
    LOGI("HiChainConnector::GetGroupInfo groupNum(%{public}u)", num);
    std::string relatedGroups = std::string(groupVec);
    deviceGroupManager_->destroyInfo(&groupVec);
    nlohmann::json jsonObject = nlohmann::json::parse(relatedGroups, nullptr, false);
    if (jsonObject.is_discarded()) {
        LOGE("returnGroups parse error");
        return false;
    }
    if (!jsonObject.is_array()) {
        LOGE("json string is not array.");
        return false;
    }
    std::vector<GroupInfo> groupInfos = jsonObject.get<std::vector<GroupInfo>>();
    if (groupInfos.size() == 0) {
        LOGE("HiChainConnector::GetGroupInfo group failed, groupInfos is empty.");
        return false;
    }
    groupList = groupInfos;
    return true;
}

DmAuthForm HiChainConnector::GetGroupType(const std::string &deviceId)
{
    std::vector<OHOS::DistributedHardware::GroupInfo> groupList;
    int32_t ret = GetRelatedGroups(deviceId, groupList);
    if (ret != DM_OK) {
        LOGE("HiChainConnector::GetGroupType get related groups failed");
        return DmAuthForm::INVALID_TYPE;
    }

    if (groupList.size() == 0) {
        LOGE("HiChainConnector::GetGroupType group list is empty");
        return DmAuthForm::INVALID_TYPE;
    }

    AuthFormPriority highestPriority = AuthFormPriority::PRIORITY_PEER_TO_PEER;
    for (auto it = groupList.begin(); it != groupList.end(); ++it) {
        if (g_authFormPriorityMap.count(it->groupType) == 0) {
            LOGE("HiChainConnector::GetGroupType unsupported auth form");
            return DmAuthForm::INVALID_TYPE;
        }
        AuthFormPriority priority = g_authFormPriorityMap.at(it->groupType);
        if (priority > highestPriority) {
            highestPriority = priority;
        }
    }

    if (highestPriority == AuthFormPriority::PRIORITY_IDENTICAL_ACCOUNT) {
        return DmAuthForm::IDENTICAL_ACCOUNT;
    } else if (highestPriority == AuthFormPriority::PRIORITY_ACROSS_ACCOUNT) {
        return DmAuthForm::ACROSS_ACCOUNT;
    } else if (highestPriority == AuthFormPriority::PRIORITY_PEER_TO_PEER) {
        return DmAuthForm::PEER_TO_PEER;
    }

    return DmAuthForm::INVALID_TYPE;
}

int32_t HiChainConnector::AddMember(const std::string &deviceId, const std::string &connectInfo)
{
    LOGI("HiChainConnector::AddMember");
    if (deviceGroupManager_ == nullptr) {
        LOGI("HiChainConnector::AddMember group manager is null.");
        return ERR_DM_POINT_NULL;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(connectInfo, nullptr, false);
    if (jsonObject.is_discarded()) {
        LOGE("DecodeRequestAuth jsonStr error");
        return ERR_DM_FAILED;
    }
    if (!IsString(jsonObject, TAG_DEVICE_ID) || !IsInt32(jsonObject, PIN_CODE_KEY) ||
        !IsString(jsonObject, TAG_GROUP_ID) || !IsInt64(jsonObject, TAG_REQUEST_ID) ||
        !IsString(jsonObject, TAG_GROUP_NAME)) {
        LOGE("HiChainConnector::AddMember err json string.");
        return ERR_DM_FAILED;
    }
    char localDeviceId[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localDeviceId, DEVICE_UUID_LENGTH);
    std::string connectInfomation = GetConnectPara(deviceId, jsonObject[TAG_DEVICE_ID].get<std::string>());

    int32_t pinCode = jsonObject[PIN_CODE_KEY].get<int32_t>();
    std::string groupId = jsonObject[TAG_GROUP_ID].get<std::string>();
    nlohmann::json jsonObj;
    jsonObj[FIELD_GROUP_ID] = groupId;
    jsonObj[FIELD_GROUP_TYPE] = GROUP_TYPE_PEER_TO_PEER_GROUP;
    jsonObj[FIELD_PIN_CODE] = std::to_string(pinCode).c_str();
    jsonObj[FIELD_IS_ADMIN] = false;
    jsonObj[FIELD_DEVICE_ID] = localDeviceId;
    jsonObj[FIELD_GROUP_NAME] = jsonObject[TAG_GROUP_NAME].get<std::string>();
    jsonObj[FIELD_CONNECT_PARAMS] = connectInfomation.c_str();
    std::string tmpStr = jsonObj.dump();
    int64_t requestId = jsonObject[TAG_REQUEST_ID].get<int64_t>();
    int32_t userId = MultipleUserConnector::GetCurrentAccountUserID();
    if (userId < 0) {
        LOGE("get current process account user id failed");
        return ERR_DM_FAILED;
    }
    int32_t ret = deviceGroupManager_->addMemberToGroup(userId, requestId, DM_PKG_NAME, tmpStr.c_str());
    if (ret != 0) {
        LOGE("[HICHAIN]fail to add number to hichain group with ret:%{public}d.", ret);
    }
    LOGI("HiChainConnector::AddMember completed");
    return ret;
}

void HiChainConnector::onFinish(int64_t requestId, int operationCode, const char *returnData)
{
    std::string data = (returnData != nullptr) ? std::string(returnData) : "";
    LOGI("HiChainConnector::onFinish reqId:%{public}" PRId64 ", operation:%{public}d", requestId, operationCode);
    if (operationCode == GroupOperationCode::MEMBER_JOIN) {
        LOGI("Add Member To Group success");
        if (!DmRadarHelper::GetInstance().ReportAuthAddGroupCb(
            "onFinish", static_cast<int32_t>(StageRes::STAGE_SUCC))) {
            LOGE("ReportAuthAddGroupCb failed");
        }
        SysEventWrite(std::string(ADD_HICHAIN_GROUP_SUCCESS), DM_HISYEVENT_BEHAVIOR,
            std::string(ADD_HICHAIN_GROUP_SUCCESS_MSG));
        if (hiChainConnectorCallback_ != nullptr) {
            hiChainConnectorCallback_->OnMemberJoin(requestId, DM_OK);
        }
    }
    if (operationCode == GroupOperationCode::GROUP_CREATE) {
        LOGI("Create group success");
        if (!DmRadarHelper::GetInstance().ReportAuthCreateGroupCb(
            "onFinish", static_cast<int32_t>(StageRes::STAGE_SUCC))) {
            LOGE("ReportAuthCreateGroupCb failed");
        }
        SysEventWrite(std::string(DM_CREATE_GROUP_SUCCESS), DM_HISYEVENT_BEHAVIOR,
            std::string(DM_CREATE_GROUP_SUCCESS_MSG));
        if (networkStyle_ == CREDENTIAL_NETWORK) {
            if (hiChainResCallback_ != nullptr) {
                int32_t importAction = 0;
                hiChainResCallback_->OnGroupResult(requestId, importAction, data);
                g_createGroupFlag = true;
            }
        } else {
            if (hiChainConnectorCallback_ != nullptr) {
                hiChainConnectorCallback_->OnMemberJoin(requestId, DM_OK);
                hiChainConnectorCallback_->OnGroupCreated(requestId, data);
            }
        }
    }
    if (operationCode == GroupOperationCode::MEMBER_DELETE) {
        LOGI("Delete Member from group success");
    }
    if (operationCode == GroupOperationCode::GROUP_DISBAND) {
        if (networkStyle_ == CREDENTIAL_NETWORK && hiChainResCallback_ != nullptr) {
            if (!g_groupIsRedundance) {
                int32_t deleteAction = 1;
                hiChainResCallback_->OnGroupResult(requestId, deleteAction, data);
            }
            g_deleteGroupFlag = true;
        }
        LOGI("Disband group success");
    }
}

void HiChainConnector::onError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
{
    std::string data = (errorReturn != nullptr) ? std::string(errorReturn) : "";
    LOGI("HichainAuthenCallBack::onError reqId:%{public}" PRId64 ", operation:%{public}d, errorCode:%{public}d.",
        requestId, operationCode, errorCode);
    if (operationCode == GroupOperationCode::MEMBER_JOIN) {
        LOGE("Add Member To Group failed");
        if (!DmRadarHelper::GetInstance().ReportAuthAddGroupCb(
            "onError", static_cast<int32_t>(StageRes::STAGE_FAIL))) {
            LOGE("ReportAuthAddGroupCb failed");
        }
        SysEventWrite(std::string(ADD_HICHAIN_GROUP_FAILED), DM_HISYEVENT_BEHAVIOR,
            std::string(ADD_HICHAIN_GROUP_FAILED_MSG));
        if (hiChainConnectorCallback_ != nullptr) {
            hiChainConnectorCallback_->OnMemberJoin(requestId, ERR_DM_FAILED);
        }
    }
    if (operationCode == GroupOperationCode::GROUP_CREATE) {
        LOGE("Create group failed");
        if (!DmRadarHelper::GetInstance().ReportAuthCreateGroupCb(
            "onError", static_cast<int32_t>(StageRes::STAGE_FAIL))) {
            LOGE("ReportAuthCreateGroupCb failed");
        }
        SysEventWrite(std::string(DM_CREATE_GROUP_FAILED), DM_HISYEVENT_BEHAVIOR,
            std::string(DM_CREATE_GROUP_FAILED_MSG));
        if (networkStyle_ == CREDENTIAL_NETWORK) {
            if (hiChainResCallback_ != nullptr) {
                int32_t importAction = 0;
                hiChainResCallback_->OnGroupResult(requestId, importAction, data);
                g_createGroupFlag = true;
            }
        } else {
            if (hiChainConnectorCallback_ != nullptr) {
                hiChainConnectorCallback_->OnGroupCreated(requestId, "{}");
            }
        }
    }
    if (operationCode == GroupOperationCode::MEMBER_DELETE) {
        LOGE("Delete Member from group failed");
    }
    if (operationCode == GroupOperationCode::GROUP_DISBAND) {
        if (networkStyle_ == CREDENTIAL_NETWORK && hiChainResCallback_ != nullptr) {
            if (!g_groupIsRedundance) {
                int32_t deleteAction = 1;
                hiChainResCallback_->OnGroupResult(requestId, deleteAction, data);
            }
            g_deleteGroupFlag = true;
        }
        LOGE("Disband group failed");
    }
}

char *HiChainConnector::onRequest(int64_t requestId, int operationCode, const char *reqParams)
{
    (void)requestId;
    (void)reqParams;
    if (operationCode != GroupOperationCode::MEMBER_JOIN) {
        LOGE("HiChainConnector::onRequest operationCode %{public}d", operationCode);
        return nullptr;
    }
    if (hiChainConnectorCallback_ == nullptr) {
        LOGE("HiChainConnector::onRequest hiChainConnectorCallback_ is nullptr.");
        return nullptr;
    }
    nlohmann::json jsonObj;
    int32_t pinCode = hiChainConnectorCallback_->GetPinCode();
    if (pinCode == ERR_DM_AUTH_NOT_START) {
        jsonObj[FIELD_CONFIRMATION] = REQUEST_REJECTED;
    } else {
        jsonObj[FIELD_CONFIRMATION] = REQUEST_ACCEPTED;
    }
    jsonObj[FIELD_PIN_CODE] = std::to_string(pinCode).c_str();
    char localDeviceId[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localDeviceId, DEVICE_UUID_LENGTH);
    jsonObj[FIELD_DEVICE_ID] = localDeviceId;

    std::string jsonStr = jsonObj.dump();
    char *buffer = strdup(jsonStr.c_str());
    return buffer;
}

int64_t HiChainConnector::GenRequestId()
{
    return GenRandLongLong(MIN_REQUEST_ID, MAX_REQUEST_ID);
}

std::string HiChainConnector::GetConnectPara(std::string deviceId, std::string reqDeviceId)
{
    LOGI("HiChainConnector::GetConnectPara get addrInfo");
    if (hiChainConnectorCallback_ == nullptr) {
        LOGE("HiChainConnector::GetConnectPara hiChainConnectorCallback_ is nullptr.");
        return "";
    }
    std::string connectAddr = hiChainConnectorCallback_->GetConnectAddr(deviceId);
    nlohmann::json jsonObject = nlohmann::json::parse(connectAddr, nullptr, false);
    if (jsonObject.is_discarded()) {
        LOGE("DecodeRequestAuth jsonStr error");
        return connectAddr;
    }
    jsonObject[DEVICE_ID] = reqDeviceId;

    return jsonObject.dump();
}

int32_t HiChainConnector::GetRelatedGroups(const std::string &deviceId, std::vector<GroupInfo> &groupList)
{
    return GetRelatedGroupsCommon(deviceId, DM_PKG_NAME, groupList);
}

int32_t HiChainConnector::GetRelatedGroupsExt(const std::string &deviceId, std::vector<GroupInfo> &groupList)
{
    return GetRelatedGroupsCommon(deviceId, DM_PKG_NAME_EXT, groupList);
}

int32_t HiChainConnector::GetSyncGroupList(std::vector<GroupInfo> &groupList, std::vector<std::string> &syncGroupList)
{
    if (groupList.empty()) {
        LOGE("groupList is empty.");
        return ERR_DM_FAILED;
    }
    for (auto group : groupList) {
        if (IsGroupInfoInvalid(group)) {
            continue;
        }
        syncGroupList.push_back(group.groupId);
    }
    return DM_OK;
}

bool HiChainConnector::IsDevicesInP2PGroup(const std::string &hostDevice, const std::string &peerDevice)
{
    LOGI("HiChainConnector::IsDevicesInP2PGroup");
    std::vector<GroupInfo> hostGroupInfoList;
    GetRelatedGroups(hostDevice, hostGroupInfoList);
    std::vector<GroupInfo> peerGroupInfoList;
    GetRelatedGroups(peerDevice, peerGroupInfoList);
    for (const auto &hostGroupInfo : hostGroupInfoList) {
        if (hostGroupInfo.groupType != GROUP_TYPE_PEER_TO_PEER_GROUP) {
            continue;
        }
        for (const auto &peerGroupInfo : peerGroupInfoList) {
            if (peerGroupInfo.groupType != GROUP_TYPE_PEER_TO_PEER_GROUP) {
                continue;
            }
            if (hostGroupInfo.groupId == peerGroupInfo.groupId && hostGroupInfo.groupName == peerGroupInfo.groupName) {
                LOGE("these are authenticated");
                return true;
            }
        }
    }
    return false;
}

bool HiChainConnector::IsGroupInfoInvalid(GroupInfo &group)
{
    if (group.groupType == GROUP_TYPE_IDENTICAL_ACCOUNT_GROUP || group.groupVisibility == GROUP_VISIBILITY_PUBLIC ||
        group.groupOwner != std::string(DM_PKG_NAME)) {
        return true;
    }
    return false;
}

int32_t HiChainConnector::SyncGroups(std::string deviceId, std::vector<std::string> &remoteGroupIdList)
{
    std::vector<GroupInfo> groupInfoList;
    GetRelatedGroups(deviceId, groupInfoList);
    for (auto &groupInfo : groupInfoList) {
        if (IsGroupInfoInvalid(groupInfo)) {
            continue;
        }
        auto iter = std::find(remoteGroupIdList.begin(), remoteGroupIdList.end(), groupInfo.groupId);
        if (iter == remoteGroupIdList.end()) {
            (void)DelMemberFromGroup(groupInfo.groupId, deviceId);
        }
    }
    return DM_OK;
}

int32_t HiChainConnector::DelMemberFromGroup(const std::string &groupId, const std::string &deviceId)
{
    int64_t requestId = GenRequestId();
    LOGI("Start to delete member from group, requestId %{public}" PRId64", deviceId %{public}s, groupId %{public}s",
        requestId, GetAnonyString(deviceId).c_str(), GetAnonyString(groupId).c_str());
    nlohmann::json jsonObj;
    jsonObj[FIELD_GROUP_ID] = groupId;
    jsonObj[FIELD_DELETE_ID] = deviceId;
    std::string deleteParams = jsonObj.dump();
    int32_t userId = MultipleUserConnector::GetCurrentAccountUserID();
    if (userId < 0) {
        LOGE("get current process account user id failed");
        return ERR_DM_FAILED;
    }
    int32_t ret = deviceGroupManager_->deleteMemberFromGroup(userId, requestId, DM_PKG_NAME, deleteParams.c_str());
    if (ret != 0) {
        LOGE("[HICHAIN]fail to delete member from group with ret:%{public}d.", ret);
        return ret;
    }
    return DM_OK;
}

int32_t HiChainConnector::DeleteGroup(std::string &groupId)
{
    int64_t requestId = GenRequestId();
    nlohmann::json jsonObj;
    jsonObj[FIELD_GROUP_ID] = groupId;
    std::string disbandParams = jsonObj.dump();
    int32_t userId = MultipleUserConnector::GetCurrentAccountUserID();
    if (userId < 0) {
        LOGE("get current process account user id failed");
        return ERR_DM_FAILED;
    }

    int32_t ret = deviceGroupManager_->deleteGroup(userId, requestId, DM_PKG_NAME, disbandParams.c_str());
    if (ret != 0) {
        LOGE("[HICHAIN]fail to delete group with ret:%{public}d.", ret);
        return ERR_DM_FAILED;
    }
    return DM_OK;
}

int32_t HiChainConnector::DeleteGroupExt(std::string &groupId)
{
    int64_t requestId = GenRequestId();
    nlohmann::json jsonObj;
    jsonObj[FIELD_GROUP_ID] = groupId;
    std::string disbandParams = jsonObj.dump();
    int32_t userId = MultipleUserConnector::GetCurrentAccountUserID();
    if (userId < 0) {
        LOGE("get current process account user id failed");
        return ERR_DM_FAILED;
    }

    int32_t ret = deviceGroupManager_->deleteGroup(userId, requestId, DM_PKG_NAME_EXT, disbandParams.c_str());
    if (ret != 0) {
        LOGE("[HICHAIN]fail to delete group with ret:%{public}d.", ret);
        return ERR_DM_FAILED;
    }
    return DM_OK;
}

int32_t HiChainConnector::DeleteGroup(const int32_t userId, std::string &groupId)
{
    int64_t requestId = GenRequestId();
    nlohmann::json jsonObj;
    jsonObj[FIELD_GROUP_ID] = groupId;
    std::string disbandParams = jsonObj.dump();
    int32_t ret = deviceGroupManager_->deleteGroup(userId, requestId, DM_PKG_NAME, disbandParams.c_str());
    if (ret != 0) {
        LOGE("[HICHAIN]fail to delete group failed, ret: %{public}d.", ret);
        return ERR_DM_FAILED;
    }
    return DM_OK;
}

int32_t HiChainConnector::DeleteGroup(int64_t requestId_, const std::string &userId, const int32_t authType)
{
    networkStyle_ = CREDENTIAL_NETWORK;
    nlohmann::json jsonObj;
    jsonObj[FIELD_GROUP_TYPE] = authType;
    std::string queryParams = jsonObj.dump();
    std::vector<GroupInfo> groupList;
    if (!GetGroupInfo(queryParams, groupList)) {
        LOGE("failed to get device join groups");
        return ERR_DM_FAILED;
    }
    LOGI("HiChainConnector::DeleteGroup groupList count = %{public}zu", groupList.size());
    bool userIsExist = false;
    std::string groupId = "";
    for (auto iter = groupList.begin(); iter != groupList.end(); iter++) {
        if (iter->userId == userId) {
            userIsExist = true;
            groupId = iter->groupId;
            break;
        }
    }
    if (!userIsExist) {
        LOGE("input userId is exist in groupList!");
        return ERR_DM_FAILED;
    }
    jsonObj[FIELD_GROUP_ID] = groupId;
    std::string disbandParams = jsonObj.dump();
    g_deleteGroupFlag = false;
    int32_t osAccountUserId = MultipleUserConnector::GetCurrentAccountUserID();
    if (osAccountUserId < 0) {
        LOGE("get current process account user id failed");
        return ERR_DM_FAILED;
    }
    int32_t ret = deviceGroupManager_->deleteGroup(osAccountUserId, requestId_, DM_PKG_NAME,
        disbandParams.c_str());
    if (ret != 0) {
        LOGE("[HICHAIN]fail to delete hichain group with ret:%{public}d.", ret);
        return ERR_DM_FAILED;
    }
    int32_t nTickTimes = 0;
    while (!g_deleteGroupFlag) {
        usleep(DELAY_TIME_MS);
        if (++nTickTimes > SERVICE_INIT_TRY_MAX_NUM) {
            LOGE("failed to delete group because timeout!");
            return ERR_DM_FAILED;
        }
    }
    return DM_OK;
}

int32_t HiChainConnector::DeleteTimeOutGroup(const char* deviceId)
{
    LOGI("HiChainConnector::DeleteTimeOutGroup start");
    int32_t userId = MultipleUserConnector::GetCurrentAccountUserID();
    if (userId < 0) {
        LOGE("get current process account user id failed");
        return ERR_DM_FAILED;
    }
    std::vector<GroupInfo> peerGroupInfoList;
    GetRelatedGroups(deviceId, peerGroupInfoList);
    char localDeviceId[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localDeviceId, DEVICE_UUID_LENGTH);
    for (auto &group : peerGroupInfoList) {
        if (!(deviceGroupManager_->isDeviceInGroup(userId, DM_PKG_NAME, group.groupId.c_str(), localDeviceId))) {
            continue;
        }
        if ((!group.groupName.empty()) && (group.groupName[CHECK_AUTH_ALWAYS_POS] == AUTH_ALWAYS)) {
            LOGI("HiChainConnector::DeleteTimeOutGroup always trusted group");
            continue;
        }
        if (group.groupType == GROUP_TYPE_PEER_TO_PEER_GROUP) {
            DeleteGroup(group.groupId);
        }
    }
    return DM_OK;
}

void HiChainConnector::DeleteRedundanceGroup(std::string &userId)
{
    int32_t nTickTimes = 0;
    g_deleteGroupFlag = false;
    DeleteGroup(userId);
    while (!g_deleteGroupFlag) {
        usleep(DELAY_TIME_MS);
        if (++nTickTimes > SERVICE_INIT_TRY_MAX_NUM) {
            LOGE("failed to delete group because timeout!");
            return;
        }
    }
}

void HiChainConnector::DealRedundanceGroup(const std::string &userId, int32_t authType)
{
    g_groupIsRedundance = false;
    std::vector<GroupInfo> groupList;
    if (IsRedundanceGroup(userId, authType, groupList)) {
        LOGI("HiChainConnector::CreateGroup IsRedundanceGroup");
        g_groupIsRedundance = true;
        for (auto iter = groupList.begin(); iter != groupList.end(); iter++) {
            if (iter->userId != userId) {
                DeleteRedundanceGroup(iter->userId);
            }
        }
        g_groupIsRedundance = false;
    }
}

int32_t HiChainConnector::CreateGroup(int64_t requestId, int32_t authType, const std::string &userId,
    nlohmann::json &jsonOutObj)
{
    LOGI("HiChainConnector::CreateGroup start.");
    if (deviceGroupManager_ == nullptr) {
        LOGE("HiChainConnector::CreateGroup group manager is null, requestId %{public}" PRId64, requestId);
        return ERR_DM_INPUT_PARA_INVALID;
    }
    DealRedundanceGroup(userId, authType);
    networkStyle_ = CREDENTIAL_NETWORK;
    LOGI("HiChainConnector::CreateGroup requestId %{public}" PRId64, requestId);
    char localDeviceId[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localDeviceId, DEVICE_UUID_LENGTH);
    std::string sLocalDeviceId = localDeviceId;
    nlohmann::json jsonObj;
    jsonObj[FIELD_GROUP_TYPE] = authType;
    jsonObj[FIELD_USER_ID] = userId;
    jsonObj[FIELD_CREDENTIAL] = jsonOutObj;
    jsonObj[FIELD_DEVICE_ID] = sLocalDeviceId;
    jsonObj[FIELD_USER_TYPE] = 0;
    jsonObj[FIELD_GROUP_VISIBILITY] = GROUP_VISIBILITY_PUBLIC;
    jsonObj[FIELD_EXPIRE_TIME] = FIELD_EXPIRE_TIME_VALUE;
    g_createGroupFlag = false;
    int32_t osAccountUserId = MultipleUserConnector::GetCurrentAccountUserID();
    if (osAccountUserId < 0) {
        LOGE("get current process account user id failed");
        return ERR_DM_FAILED;
    }

    int32_t ret = deviceGroupManager_->createGroup(osAccountUserId, requestId, DM_PKG_NAME, jsonObj.dump().c_str());
    if (ret != DM_OK) {
        LOGE("[HICHAIN]fail to create group with ret:%{public}d, requestId:%{public}" PRId64, ret, requestId);
        return ERR_DM_CREATE_GROUP_FAILED;
    }
    int32_t nTickTimes = 0;
    while (!g_createGroupFlag) {
        usleep(DELAY_TIME_MS);
        if (++nTickTimes > SERVICE_INIT_TRY_MAX_NUM) {
            LOGE("failed to create group because timeout!");
            return ERR_DM_FAILED;
        }
    }
    return DM_OK;
}

int32_t HiChainConnector::RegisterHiChainGroupCallback(const std::shared_ptr<IDmGroupResCallback> &callback)
{
    hiChainResCallback_ = callback;
    return DM_OK;
}

int32_t HiChainConnector::UnRegisterHiChainGroupCallback()
{
    hiChainResCallback_ = nullptr;
    return DM_OK;
}

int32_t HiChainConnector::getRegisterInfo(const std::string &queryParams, std::string &returnJsonStr)
{
    if (deviceGroupManager_ == nullptr) {
        LOGE("HiChainConnector::deviceGroupManager_ is nullptr.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    char *credentialInfo = nullptr;
    if (deviceGroupManager_->getRegisterInfo(queryParams.c_str(), &credentialInfo) != DM_OK) {
        LOGE("[HICHAIN]fail to request hichain registerinfo.");
        return ERR_DM_FAILED;
    }

    returnJsonStr = credentialInfo;
    deviceGroupManager_->destroyInfo(&credentialInfo);
    LOGI("request hichain device registerinfo successfully.");
    return DM_OK;
}

int32_t HiChainConnector::GetGroupId(const std::string &userId, const int32_t groupType, std::string &groupId)
{
    nlohmann::json jsonObjGroup;
    jsonObjGroup[FIELD_GROUP_TYPE] = groupType;
    std::string queryParams = jsonObjGroup.dump();
    std::vector<GroupInfo> groupList;

    if (!GetGroupInfo(queryParams.c_str(), groupList)) {
        LOGE("failed to get device join groups");
        return ERR_DM_FAILED;
    }
    for (auto &groupinfo : groupList) {
        LOGI("groupinfo.groupId:%{public}s", GetAnonyString(groupinfo.groupId).c_str());
        if (groupinfo.userId == userId) {
            groupId = groupinfo.groupId;
            return DM_OK;
        }
    }
    return ERR_DM_FAILED;
}

int32_t HiChainConnector::ParseRemoteCredential(const int32_t groupType, const std::string &userId,
    const nlohmann::json &jsonDeviceList, std::string &params, int32_t &osAccountUserId)
{
    if (userId.empty() || !jsonDeviceList.contains(FIELD_DEVICE_LIST)) {
        LOGE("userId or deviceList is empty");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    std::string groupId;
    if (GetGroupId(userId, groupType, groupId) != DM_OK) {
        LOGE("failed to get groupid");
        return ERR_DM_FAILED;
    }
    nlohmann::json jsonObj;
    jsonObj[FIELD_GROUP_ID] = groupId;
    jsonObj[FIELD_GROUP_TYPE] = groupType;
    jsonObj[FIELD_DEVICE_LIST] = jsonDeviceList[FIELD_DEVICE_LIST];
    params = jsonObj.dump();
    osAccountUserId = MultipleUserConnector::GetCurrentAccountUserID();
    if (osAccountUserId < 0) {
        LOGE("get current process account user id failed");
        return ERR_DM_FAILED;
    }
    return DM_OK;
}

int32_t HiChainConnector::addMultiMembers(const int32_t groupType, const std::string &userId,
    const nlohmann::json &jsonDeviceList)
{
    if (deviceGroupManager_ == nullptr) {
        LOGE("HiChainConnector::deviceGroupManager_ is nullptr.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    std::string addParams;
    int32_t osAccountUserId = 0;
    if (ParseRemoteCredential(groupType, userId, jsonDeviceList, addParams, osAccountUserId) != DM_OK) {
        LOGE("addMultiMembers ParseRemoteCredential failed!");
        return ERR_DM_FAILED;
    }

    int32_t ret = deviceGroupManager_->addMultiMembersToGroup(osAccountUserId, DM_PKG_NAME, addParams.c_str());
    if (ret != DM_OK) {
        LOGE("[HICHAIN]fail to add member to hichain group with ret:%{public}d.", ret);
        return ret;
    }
    return DM_OK;
}

std::string HiChainConnector::GetJsonStr(const nlohmann::json &jsonObj, const std::string &key)
{
    if (!IsString(jsonObj, key)) {
        LOGE("User string key not exist!");
        return "";
    }
    return jsonObj[key].get<std::string>();
}

int32_t HiChainConnector::GetJsonInt(const nlohmann::json &jsonObj, const std::string &key)
{
    if (!IsInt32(jsonObj, key)) {
        LOGE("User string key not exist!");
        return ERR_DM_FAILED;
    }
    return jsonObj[key].get<int32_t>();
}

int32_t HiChainConnector::GetGroupIdExt(const std::string &userId, const int32_t groupType,
    std::string &groupId, std::string &groupOwner)
{
    nlohmann::json jsonObjGroup;
    jsonObjGroup[FIELD_GROUP_TYPE] = groupType;
    std::string queryParams = jsonObjGroup.dump();
    std::vector<GroupInfo> groupList;

    if (!GetGroupInfo(queryParams.c_str(), groupList)) {
        LOGE("failed to get device join groups");
        return ERR_DM_FAILED;
    }
    for (auto &groupinfo : groupList) {
        LOGI("groupinfo.groupId:%{public}s", GetAnonyString(groupinfo.groupId).c_str());
        if (groupinfo.userId == userId) {
            groupId = groupinfo.groupId;
            groupOwner = groupinfo.groupOwner;
            return DM_OK;
        }
    }
    return ERR_DM_FAILED;
}

int32_t HiChainConnector::ParseRemoteCredentialExt(const std::string &credentialInfo, std::string &params,
    std::string &groupOwner)
{
    LOGI("ParseRemoteCredentialExt start.");
    nlohmann::json jsonObject = nlohmann::json::parse(credentialInfo, nullptr, false);
    if (jsonObject.is_discarded()) {
        LOGE("CredentialInfo string not a json type.");
        return ERR_DM_FAILED;
    }
    nlohmann::json jsonObj;
    int32_t groupType = 0;
    std::string userId = "";
    int32_t authType = GetJsonInt(jsonObject, AUTH_TYPE);
    if (authType == SAME_ACCOUNT) {
        groupType = IDENTICAL_ACCOUNT_GROUP;
        userId = GetJsonStr(jsonObject, FIELD_USER_ID);
    } else {
        LOGE("Failed to get userId.");
        return ERR_DM_FAILED;
    }
    std::string groupId = "";
    if (GetGroupIdExt(userId, groupType, groupId, groupOwner) != DM_OK) {
        LOGE("Failed to get groupid");
        return ERR_DM_FAILED;
    }
    jsonObj[FIELD_GROUP_TYPE] = groupType;
    jsonObj[FIELD_GROUP_ID] = groupId;
    jsonObj[FIELD_USER_ID] = userId;
    jsonObj[FIELD_CREDENTIAL_TYPE] = GetJsonInt(jsonObject, FIELD_CREDENTIAL_TYPE);
    jsonObj[FIELD_OPERATION_CODE] = GetJsonInt(jsonObject, FIELD_OPERATION_CODE);
    jsonObj[FIELD_META_NODE_TYPE] = GetJsonStr(jsonObject, FIELD_TYPE);
    if (!jsonObject.contains(FIELD_DEVICE_LIST)) {
        LOGE("Credentaildata or authType string key not exist!");
        return ERR_DM_FAILED;
    }
    jsonObj[FIELD_DEVICE_LIST] = jsonObject[FIELD_DEVICE_LIST];
    params = jsonObj.dump();
    return DM_OK;
}

int32_t HiChainConnector::addMultiMembersExt(const std::string &credentialInfo)
{
    if (deviceGroupManager_ == nullptr) {
        LOGE("HiChainConnector::deviceGroupManager_ is nullptr.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    std::string addParams = "";
    std::string groupOwner = "";
    if (ParseRemoteCredentialExt(credentialInfo, addParams, groupOwner) != DM_OK) {
        LOGE("AddMultiMembers ParseRemoteCredentialExt failed!");
        return ERR_DM_FAILED;
    }
    int32_t osAccountUserId = MultipleUserConnector::GetCurrentAccountUserID();
    if (osAccountUserId < 0) {
        LOGE("Get current process account user id failed");
        return ERR_DM_FAILED;
    }
    int32_t ret = deviceGroupManager_->addMultiMembersToGroup(osAccountUserId, groupOwner.c_str(), addParams.c_str());
    if (ret != DM_OK) {
        LOGE("[HICHAIN]fail to add member to hichain group with ret:%{public}d.", ret);
        return ret;
    }
    return DM_OK;
}

int32_t HiChainConnector::deleteMultiMembers(const int32_t groupType, const std::string &userId,
    const nlohmann::json &jsonDeviceList)
{
    if (deviceGroupManager_ == nullptr) {
        LOGE("HiChainConnector::deviceGroupManager_ is nullptr.");
        return ERR_DM_INPUT_PARA_INVALID;
    }

    std::string deleteParams;
    int32_t osAccountUserId = 0;
    if (ParseRemoteCredential(groupType, userId, jsonDeviceList, deleteParams, osAccountUserId) != DM_OK) {
        LOGE("deleteMultiMembers ParseRemoteCredential failed!");
        return ERR_DM_FAILED;
    }

    int32_t ret = deviceGroupManager_->delMultiMembersFromGroup(osAccountUserId, DM_PKG_NAME, deleteParams.c_str());
    if (ret != DM_OK) {
        LOGE("[HICHAIN]fail to delete member from hichain group with ret:%{public}d.", ret);
        return ret;
    }
    return DM_OK;
}

std::vector<std::string> HiChainConnector::GetTrustedDevices(const std::string &localDeviceUdid)
{
    LOGI("get localDeviceUdid: %{public}s trusted devices.", GetAnonyString(localDeviceUdid).c_str());
    std::vector<GroupInfo> groups;
    int32_t ret = GetRelatedGroups(localDeviceUdid, groups);
    if (ret != DM_OK) {
        LOGE("failed to get groupInfo, ret: %{public}d", ret);
        return {};
    }

    int32_t userId = MultipleUserConnector::GetCurrentAccountUserID();
    if (userId < 0) {
        LOGE("get current process account user id failed");
        return {};
    }
    std::vector<std::string> trustedDevices;
    for (const auto &group : groups) {
        char *devicesJson = nullptr;
        uint32_t devNum = 0;
        ret = deviceGroupManager_->getTrustedDevices(userId, DM_PKG_NAME, group.groupId.c_str(),
        &devicesJson, &devNum);
        if (ret != 0 || devicesJson == nullptr) {
            LOGE("[HICHAIN]failed to get trusted devicesJson, ret: %{public}d", ret);
            return {};
        }
        GetTrustedDevicesUdid(devicesJson, trustedDevices);
        deviceGroupManager_->destroyInfo(&devicesJson);
    }
    return trustedDevices;
}

int32_t HiChainConnector::GetTrustedDevicesUdid(const char* jsonStr, std::vector<std::string> &udidList)
{
    nlohmann::json jsonObject = nlohmann::json::parse(jsonStr, nullptr, false);
    if (jsonObject.is_discarded()) {
        LOGE("credentialInfo string not a json type.");
        return ERR_DM_FAILED;
    }
    for (nlohmann::json::iterator it1 = jsonObject.begin(); it1 != jsonObject.end(); it1++) {
        if (!IsString((*it1), FIELD_AUTH_ID)) {
            continue;
        }
        std::string udid = (*it1)[FIELD_AUTH_ID];
        udidList.push_back(udid);
    }
    return DM_OK;
}

void HiChainConnector::DeleteAllGroup(int32_t userId)
{
    LOGI("HiChainConnector::DeleteAllGroup");
    char localDeviceId[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localDeviceId, DEVICE_UUID_LENGTH);
    std::string localUdid = static_cast<std::string>(localDeviceId);
    std::vector<GroupInfo> groupList;
    GetRelatedGroups(localUdid, groupList);
    for (auto &iter : groupList) {
        if (DeleteGroup(iter.groupId) != DM_OK) {
            LOGE("Delete groupId %{public}s failed.", GetAnonyString(iter.groupId).c_str());
        }
    }
    std::vector<GroupInfo> groupListExt;
    GetRelatedGroupsExt(localUdid, groupListExt);
    for (auto &iter : groupListExt) {
        if (DeleteGroupExt(iter.groupId) != DM_OK) {
            LOGE("DeleteGroupExt groupId %{public}s failed.", GetAnonyString(iter.groupId).c_str());
        }
    }
}

void HiChainConnector::DeleteP2PGroup(int32_t userId)
{
    LOGI("switch user event happen and this user groups will be deleted with userId: %{public}d", userId);
    nlohmann::json jsonObj;
    jsonObj[FIELD_GROUP_TYPE] = GROUP_TYPE_PEER_TO_PEER_GROUP;
    std::string queryParams = jsonObj.dump();
    std::vector<GroupInfo> groupList;

    int32_t oldUserId = MultipleUserConnector::GetSwitchOldUserId();
    MultipleUserConnector::SetSwitchOldUserId(userId);
    if (!GetGroupInfo(oldUserId, queryParams, groupList)) {
        LOGE("failed to get the old user id groups");
        return;
    }
    for (auto iter = groupList.begin(); iter != groupList.end(); iter++) {
        int32_t ret = DeleteGroup(oldUserId, iter->groupId);
        if (ret != DM_OK) {
            LOGE("failed to delete the old user id group");
        }
    }

    if (!GetGroupInfo(userId, queryParams, groupList)) {
        LOGE("failed to get the user id groups");
        return;
    }
    for (auto iter = groupList.begin(); iter != groupList.end(); iter++) {
        int32_t ret = DeleteGroup(userId, iter->groupId);
        if (ret != DM_OK) {
            LOGE("failed to delete the user id group");
        }
    }
}

int32_t HiChainConnector::GetRelatedGroupsCommon(const std::string &deviceId, const char* pkgName,
    std::vector<GroupInfo> &groupList)
{
    LOGI("HiChainConnector::GetRelatedGroupsCommon Start to get local related groups.");
    uint32_t groupNum = 0;
    char *returnGroups = nullptr;
    int32_t userId = MultipleUserConnector::GetCurrentAccountUserID();
    if (userId < 0) {
        LOGE("get current process account user id failed");
        return ERR_DM_FAILED;
    }
    int32_t ret =
        deviceGroupManager_->getRelatedGroups(userId, pkgName, deviceId.c_str(), &returnGroups, &groupNum);
    if (ret != 0) {
        LOGE("[HICHAIN] fail to get related groups with ret:%{public}d.", ret);
        return ERR_DM_FAILED;
    }
    if (returnGroups == nullptr) {
        LOGE("[HICHAIN] return related goups point is nullptr");
        return ERR_DM_FAILED;
    }
    if (groupNum == 0) {
        LOGE("[HICHAIN]return related goups number is zero.");
        return ERR_DM_FAILED;
    }
    std::string relatedGroups = std::string(returnGroups);
    nlohmann::json jsonObject = nlohmann::json::parse(relatedGroups, nullptr, false);
    if (jsonObject.is_discarded()) {
        LOGE("returnGroups parse error");
        return ERR_DM_FAILED;
    }
    if (!jsonObject.is_array()) {
        LOGE("jsonObject is not an array.");
        return ERR_DM_FAILED;
    }
    std::vector<GroupInfo> groupInfos = jsonObject.get<std::vector<GroupInfo>>();
    if (groupInfos.empty()) {
        LOGE("HiChainConnector::GetRelatedGroups group failed, groupInfos is empty.");
        return ERR_DM_FAILED;
    }
    groupList = groupInfos;
    return DM_OK;
}

} // namespace DistributedHardware
} // namespace OHOS