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

#ifndef OHOS_HICHAIN_ADAPTER_H
#define OHOS_HICHAIN_ADAPTER_H

#include <cstring>
#include <map>
#include <memory>
#include <stdint.h>
#include <vector>

#include "device_auth.h"
#include "event_handler.h"
#include "nlohmann/json.hpp"
#include "thread_pool.h"

#include "device_client_channel.h"
#include "device_server_channel.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedHardware {
enum {
    SUCCESS = 0,
    GROUP_CREATE_FAILED = 1,
    MEMBER_ADD_FAILED = 2,
    CREATE_CHANNEL_FAILED = 3,
};

struct DeviceReqInfo {
    std::string deviceId;
    std::string ipAddr;
    short port;
};

class BindCallback {
public:
    virtual void onBindSuccess(std::string deviceId, const char* returnData) = 0;
    virtual void onBindFailed(std::string deviceId, int32_t errorCode) = 0;
    virtual void onUnBindSuccess(std::string /* deviceId */, const char* /* returnData */) {}
    virtual void onUnBindFailed(std::string /* deviceId */, int32_t /* errorCode*/) {}
    virtual ~BindCallback() {}
};

class HichainAuthCallBack {
public:
    static bool onTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen);
    static void onSessionKeyReturned(int64_t requestId, const uint8_t *sessionKey, uint32_t sessionKeyLen);
    static void onFinish(int64_t requestId, int operationCode, const char *returnData);
    static void onError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn);
    static char* onBindRequest(int64_t requestId, int operationCode, const char *reqParams);
};

class HichainAdapter {
DECLARE_SINGLE_INSTANCE(HichainAdapter);
public:
    int Init();

    int32_t Bind(const DeviceReqInfo& devReqInfo, std::shared_ptr<BindCallback> callback, bool sync = false);

    void OnBindSuccess(int64_t requestId, const char* returnData);
    void OnBindFailed(int64_t requestId, int32_t errorCode);

    void UnBind(const std::string& deviceId);
    void OnUnBindFinished();

    bool OnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen);

    void OnGroupCreated(int64_t requestId, const char *groupInfo);

    char* OnBindRequest(int64_t requestId, int operationCode, const char *reqParams);

private:
    std::string GetGroupIdByName(int32_t groupType, const std::string& groupName);
    int32_t CreateGroup(int64_t requestId);
    int32_t AddMemeber(int64_t requestId, std::string& groupId, const std::string& pinCode);
    int64_t GenRequestId();

private:
    std::atomic<int32_t> requestIdIndex_ {0};
    std::map<int64_t, std::string> bindingDeviceMap_;
    std::map<int64_t, std::shared_ptr<DeviceClientChannel>> clientBindReqMap_;
    std::map<int64_t, std::shared_ptr<BindCallback>> bindCallBackMap_;
    const DeviceGroupManager* deviceGroupManager_ = nullptr;
    std::unique_ptr<DeviceServerChannel> deviceServerInst_;
    mutable ThreadPool threadPool_;

    DeviceAuthCallback deviceAuthCallback_ = {
        .onTransmit = HichainAuthCallBack::onTransmit,
        .onSessionKeyReturned = HichainAuthCallBack::onSessionKeyReturned,
        .onFinish = HichainAuthCallBack::onFinish,
        .onError = HichainAuthCallBack::onError,
        .onRequest = HichainAuthCallBack::onBindRequest,
    };

    // call back for socket channel
    std::function<void(int64_t, int, int, const char*)> onError_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_HICHAIN_ADAPTER_H