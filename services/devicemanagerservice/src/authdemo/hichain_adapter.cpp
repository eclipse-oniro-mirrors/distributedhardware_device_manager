/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "hichain_adapter.h"

#include <cstdlib>
#include <ctime>
#include <functional>

#include "parameter.h"

#include "anonymous_string.h"
#include "device_client_channel.h"
#include "device_manager_log.h"
#include "device_server_channel.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
// demo solution, may has security issues, later will be replaced by a formal plan
const std::string PIN_CODE = "";
const int32_t PORT = -1;

const std::string DEVICE_MANAGER_APP = "ohos.distributedhardware.devicemanager";
const std::string DEVICE_MANAGER_GROUPNAME = "DMPeerToPeerGroup";

const int64_t MIN_REQUEST_ID = 1000000000;
const int64_t MAX_REQUEST_ID = 9999999999;

const int32_t DEVICE_UUID_LENGTH = 65;
const int32_t PEER_TO_PEER_GROUP = 256;
const int32_t FIELD_EXPIRE_TIME_VALUE = 90;

const int32_t THREAD_POOL_NUMBER = 20;
}

IMPLEMENT_SINGLE_INSTANCE(HichainAdapter);

int HichainAdapter::Init()
{
    HILOGI("HichainAdapter::init, begin to init hichain adapter.");
    if (threadPool_.GetThreadsNum() == 0) {
        threadPool_.Start(THREAD_POOL_NUMBER);
    }

    bindingDeviceMap_.clear();
    bindCallBackMap_.clear();
    clientBindReqMap_.clear();

    // call back for socket channel
    using std::placeholders::_1;
    using std::placeholders::_2;
    using std::placeholders::_3;
    using std::placeholders::_4;
    onError_ = std::bind(HichainAuthCallBack::onError, _1, _2, _3, _4);

    HILOGI("HichainAdapter::init, init device auth service.");
    InitDeviceAuthService();

    // get group auth manager instance, and register callback
    deviceGroupManager_ = GetGmInstance();
    if (deviceGroupManager_ == nullptr) {
        HILOGE("HichainAdapter::init, failed to init group manager!");
        return -1;
    }
    deviceGroupManager_->regCallback(DEVICE_MANAGER_APP.c_str(), &deviceAuthCallback_);

    HILOGI("HichainAdapter::init, start socket server channel.");
    deviceServerInst_ = std::make_unique<DeviceServerChannel>(*deviceGroupManager_, onError_);
    if (deviceServerInst_->Start(PORT) == -1) {
        HILOGE("HichainAdapter::init, failed to start server!");
        return -1;
    }

    // start the server channel to receive data
    auto receiveFunc = [this]() {
        this->deviceServerInst_->Receive();
    };
    threadPool_.AddTask(receiveFunc);

    HILOGI("HichainAdapter::init, init hichain adapter success.");
    return 0;
}

int32_t HichainAdapter::Bind(const DeviceReqInfo& devReqInfo, std::shared_ptr<BindCallback> callback, bool sync)
{
    (void)sync;
    HILOGI("HichainAdapter::Bind, begin to bind device: %{public}s.", GetAnonyString(devReqInfo.deviceId).c_str());
    for (auto &item : bindingDeviceMap_) {
        if (item.second == devReqInfo.deviceId) {
            HILOGW("HichainAdapter::bind device is binding, update call back.");
        }
    }

    int64_t requestId = GenRequestId();
    std::shared_ptr<DeviceClientChannel> clientChannel =
        std::make_shared<DeviceClientChannel>(requestId, *deviceGroupManager_, onError_);
    if (clientChannel->Connect(devReqInfo.ipAddr, PORT) == -1) {
        HILOGE("HichainAdapter::bind failed to connect to server, create channel failed.");
        return CREATE_CHANNEL_FAILED;
    }

    // start the client channel to recevice data
    auto receiveFunc = [&clientChannel]() {
        clientChannel->Receive();
    };
    threadPool_.AddTask(receiveFunc);

    std::string groupId = GetGroupIdByName(PEER_TO_PEER_GROUP, DEVICE_MANAGER_GROUPNAME);
    if (groupId == "") {
        HILOGE("HichainAdapter::bind group not exist, begin to create group.");
        int32_t ret = CreateGroup(requestId);
        if (ret != 0) {
            HILOGE("HichainAdapter::bind faild to start create group task, ret: %{public}d.", ret);
            return GROUP_CREATE_FAILED;
        }
    } else {
        HILOGE("HichainAdapter::bind group exist, begin to add member.");
        int ret = AddMemeber(requestId, groupId, PIN_CODE);
        if (ret != 0) {
            HILOGE("HichainAdapter::bind faild to start add member task, ret: %{public}d.", ret);
            return MEMBER_ADD_FAILED;
        }
    }

    clientBindReqMap_[requestId] = clientChannel;
    bindingDeviceMap_[requestId] = devReqInfo.deviceId;
    bindCallBackMap_[requestId] = callback;
    return SUCCESS;
}

std::string HichainAdapter::GetGroupIdByName(int32_t groupType, const std::string& groupName)
{
    HILOGI("HichainAdapter::GetGroupIdByName get group info.");
    if (deviceGroupManager_ == nullptr) {
        HILOGE("HichainAdapter::GetGroupIdByName group manager is null.");
        return "";
    }

    nlohmann::json reqParam;
    reqParam[FIELD_GROUP_TYPE] = groupType;
    reqParam[FIELD_GROUP_NAME] = groupName;

    char* returnGroupVec = nullptr;
    uint32_t groupNum = 0;
    int32_t ret = deviceGroupManager_->getGroupInfo(DEVICE_MANAGER_APP.c_str(), reqParam.dump().c_str(),
        &returnGroupVec, &groupNum);
    if (ret != 0) {
        HILOGE("HichainAdapter::GetGroupIdByName failed to get group info, ret=%{public}d.", ret);
        return "";
    }

    if (groupNum == 0) {
        HILOGE("HichainAdapter::GetGroupIdByName group not exist, return empty.");
        return "";
    }

    nlohmann::json groupObj = nlohmann::json::parse(returnGroupVec, nullptr, false);
    if (groupObj.is_discarded()) {
        HILOGE("HichainAdapter::GetGroupIdByName parse group info error, json invalid.");
        return "";
    }

    for (auto& item : groupObj) {
        if (item.contains(FIELD_GROUP_ID)) {
            return item.at(FIELD_GROUP_ID);
        }
    }

    HILOGI("HichainAdapter::GetGroupIdByName group info not found, return empty");
    return "";
}

int32_t HichainAdapter::CreateGroup(int64_t requestId)
{
    HILOGE("HichainAdapter::CreateGroup requestId:%{public}lld.", requestId);
    if (deviceGroupManager_ == nullptr) {
        HILOGE("HichainAdapter::CreateGroup group manager is null.");
        return -1;
    }

    nlohmann::json jsonObj;
    jsonObj[FIELD_GROUP_TYPE] = PEER_TO_PEER_GROUP;
    jsonObj[FIELD_GROUP_NAME] = DEVICE_MANAGER_GROUPNAME;

    char localDeviceId[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localDeviceId, DEVICE_UUID_LENGTH);

    jsonObj[FIELD_DEVICE_ID] = localDeviceId;
    jsonObj[FIELD_USER_TYPE] = 0;
    jsonObj[FIELD_GROUP_VISIBILITY] = -1;
    jsonObj[FIELD_EXPIRE_TIME] = FIELD_EXPIRE_TIME_VALUE;

    return deviceGroupManager_->createGroup(requestId, DEVICE_MANAGER_APP.c_str(), jsonObj.dump().c_str());
}

int32_t HichainAdapter::AddMemeber(int64_t requestId, std::string& groupId, const std::string& pinCode)
{
    HILOGE("HichainAdapter::AddMemeber requestId:%{public}lld.", requestId);
    if (deviceGroupManager_ == nullptr) {
        HILOGE("HichainAdapter::AddMemeber group manager is null.");
        return -1;
    }

    nlohmann::json jsonObj;
    jsonObj[FIELD_GROUP_ID] = groupId;
    jsonObj[FIELD_GROUP_TYPE] = PEER_TO_PEER_GROUP;
    jsonObj[FIELD_PIN_CODE] = pinCode;
    jsonObj[FIELD_IS_ADMIN] = true;
    return deviceGroupManager_->addMemberToGroup(requestId, DEVICE_MANAGER_APP.c_str(), jsonObj.dump().c_str());
}

bool HichainAdapter::OnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    HILOGI("HichainAdapter::OnTransmit requestId:%{public}lld, size:%{public}d.", requestId, dataLen);
    if (clientBindReqMap_.count(requestId) > 0) {
        HILOGI("HichainAdapter::OnTransmit client send to server.");
        return clientBindReqMap_[requestId]->Send((const char*) data, dataLen);
    } else {
        HILOGI("HichainAdapter::OnTransmit server send to client.");
        return deviceServerInst_->Send((const char*) data, dataLen);
    }
}

void HichainAdapter::OnGroupCreated(int64_t requestId, const char *groupInfo)
{
    nlohmann::json jsonObject = nlohmann::json::parse(groupInfo);
    if (jsonObject.find(FIELD_GROUP_ID) == jsonObject.end()) {
        HILOGE("HichainAdapter::onGroupCreated failed to get groupId.");
        OnBindFailed(requestId, GROUP_CREATE_FAILED);
        return;
    }

    std::string groupId = jsonObject.at(FIELD_GROUP_ID).get<std::string>();
    HILOGI("HichainAdapter::onGroupCreated group create success,groupId:%{public}s.", GetAnonyString(groupId).c_str());

    // group创建成功之后，需要添加把对端设备添加到创建好的群组中
    int ret = AddMemeber(requestId, groupId, PIN_CODE);
    if (ret != 0) {
        HILOGE("HichainAdapter::onGroupCreated faild to start add member task, ret: %{public}d.", ret);
        OnBindFailed(requestId, MEMBER_ADD_FAILED);
        return;
    }
}

char* HichainAdapter::OnBindRequest(int64_t requestId, int operationCode, const char *reqParams)
{
    (void)requestId;
    (void)operationCode;
    (void)reqParams;

    HILOGI("HichainAdapter::OnBindRequest.");
    bindRequestJsonObj_.clear();
    bindRequestJsonObj_[FIELD_CONFIRMATION] = REQUEST_ACCEPTED;
    bindRequestJsonObj_[FIELD_PIN_CODE] = PIN_CODE;
    char localDeviceId[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localDeviceId, DEVICE_UUID_LENGTH);
    bindRequestJsonObj_[FIELD_DEVICE_ID] = localDeviceId;
    return (char*) bindRequestJsonObj_.dump().c_str();
}

void HichainAdapter::OnBindSuccess(int64_t requestId, const char* returnData)
{
    HILOGI("HichainAdapter::OnBindSuccess requestId:%{public}lld,dataLen:%{public}d.", requestId, strlen(returnData));
    if (bindCallBackMap_.count(requestId) == 1) {
        bindCallBackMap_[requestId]->onBindSuccess(bindingDeviceMap_[requestId], returnData);
        bindCallBackMap_.erase(requestId);
    }

    if (clientBindReqMap_.count(requestId) == 1) {
        clientBindReqMap_[requestId]->ResetConnection();
        clientBindReqMap_[requestId].reset();
        clientBindReqMap_.erase(requestId);
    }

    if (bindingDeviceMap_.count(requestId) == 1) {
        bindingDeviceMap_.erase(requestId);
    }

    deviceServerInst_->ResetConnection();
}

int64_t HichainAdapter::GenRequestId()
{
    int64_t requestId = 0;
    do {
        requestId = (int64_t)requestIdIndex_ + MIN_REQUEST_ID;
        if (requestId > MAX_REQUEST_ID) {
            requestId = MIN_REQUEST_ID;
            requestIdIndex_ = 0;
        } else {
            requestIdIndex_++;
        }
    } while (clientBindReqMap_.count(requestId) != 0);
    return requestId;
}

void HichainAdapter::OnBindFailed(int64_t requestId, int32_t errorCode)
{
    HILOGI("HichainAdapter::OnBindFailed requestId:%{public}lld, errorCode:%{public}d.", requestId, errorCode);
    if (bindCallBackMap_.count(requestId) == 1) {
        bindCallBackMap_[requestId]->onBindFailed(bindingDeviceMap_[requestId], errorCode);
        bindCallBackMap_.erase(requestId);
    }

    if (clientBindReqMap_.count(requestId) == 1) {
        clientBindReqMap_[requestId].reset();
        clientBindReqMap_.erase(requestId);
    }

    if (bindingDeviceMap_.count(requestId) == 1) {
        bindingDeviceMap_.erase(requestId);
    }
}

void HichainAdapter::UnBind(const std::string& deviceId)
{
    // reserved interface, to be implemented
    (void)deviceId;
}

void HichainAdapter::OnUnBindFinished()
{
    // reserved interface, to be implemented
}

bool HichainAuthCallBack::onTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    HILOGI("HichainAuthCallBack::onTransmit requestId:%{public}lld,size:%{public}d.", requestId, dataLen);
    return HichainAdapter::GetInstance().OnTransmit(requestId, data, dataLen);
}

void HichainAuthCallBack::onSessionKeyReturned(int64_t requestId, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    (void)requestId;
    (void)sessionKey;
    HILOGI("HichainAuthCallBack::onSessionKeyReturned size:%{public}d.", sessionKeyLen);
}

void HichainAuthCallBack::onFinish(int64_t requestId, int operationCode, const char *returnData)
{
    HILOGI("HichainAuthCallBack::onFinish reqId:%{public}lld, operation:%{public}d.", requestId, operationCode);
    if (operationCode == GroupOperationCode::GROUP_CREATE) {
        HichainAdapter::GetInstance().OnGroupCreated(requestId, returnData);
        return;
    }

    if (operationCode == GroupOperationCode::MEMBER_INVITE || operationCode == GroupOperationCode::MEMBER_JOIN) {
        HichainAdapter::GetInstance().OnBindSuccess(requestId, returnData);
    }
}

void HichainAuthCallBack::onError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
{
    (void)errorReturn;
    HILOGI("HichainAuthCallBack::onError reqId:%{public}lld, operation:%{public}d, errorCode:%{public}d.",
        requestId, operationCode, errorCode);
    HichainAdapter::GetInstance().OnBindFailed(requestId, errorCode);
}

char* HichainAuthCallBack::onBindRequest(int64_t requestId, int operationCode, const char *reqParams)
{
    HILOGI("HichainAuthCallBack::onBindRequest reqId:%{public}lld, operation:%{public}d.", requestId, operationCode);
    return HichainAdapter::GetInstance().OnBindRequest(requestId, operationCode, reqParams);
}
}
}
