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

#ifndef OHOS_DEVICE_SERVER_CHANNEL_H
#define OHOS_DEVICE_SERVER_CHANNEL_H

#include <functional>
#include <stdint.h>
#include <sys/socket.h>

#include "device_auth.h"

namespace OHOS {
namespace DistributedHardware {
class DeviceServerChannel {
public:
    DeviceServerChannel(const DeviceGroupManager& deviceGroupManager,
        std::function<void(int64_t, int, int, const char*)> onError)
        : socketFd_(-1), clientFd_(-1), deviceGroupManager_(deviceGroupManager), onError_(onError) {}
    ~DeviceServerChannel();

    DeviceServerChannel()=delete;
    DeviceServerChannel(const DeviceServerChannel&)=delete;
    DeviceServerChannel &operator=(const DeviceServerChannel&)=delete;

public:
    int32_t Start(const int32_t port);
    bool Send(const char* data, const int32_t dataLen);
    void Receive();
    void OnDataReceived(const char* data, const int32_t dataLen);
    void ResetConnection();

private:
    int32_t socketFd_;
    int32_t clientFd_;
    const DeviceGroupManager& deviceGroupManager_;
    std::function<void(int64_t, int, int, const char*)> onError_;
};
}
}
#endif