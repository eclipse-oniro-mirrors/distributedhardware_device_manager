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

#ifndef OHOS_DEVICE_CLIENT_CHANNEL_H
#define OHOS_DEVICE_CLIENT_CHANNEL_H

#include <functional>
#include <string>

#include "device_auth.h"

namespace OHOS {
namespace DistributedHardware {
class DeviceClientChannel {
public:
    DeviceClientChannel(int64_t requestId, const DeviceGroupManager& deviceGroupManager,
        std::function<void(int64_t, int, int, const char*)> onError)
        : requestId_(requestId), socketFd_(-1), deviceGroupManager_(deviceGroupManager), onError_(onError) {}
    ~DeviceClientChannel();

    DeviceClientChannel()=delete;
    DeviceClientChannel(const DeviceClientChannel&)=delete;
    DeviceClientChannel &operator=(const DeviceClientChannel&)=delete;

public:
    int32_t Connect(const std::string& ip, short port);
    bool Send(const char* data, const int32_t dataLen);
    void Receive(void);
    void OnDataReceived(const char* data, const int32_t dataLen);
    void ResetConnection();

private:
    int64_t requestId_;
    int32_t socketFd_;
    const DeviceGroupManager& deviceGroupManager_;
    // call back for socket channel
    std::function<void(int64_t, int, int, const char*)> onError_;
};
}
}
#endif