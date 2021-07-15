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

#include "device_client_channel.h"

#include <cstdlib>
#include <cstring>

#include <errno.h>
#include <memory>
#include <sstream>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <securec.h>

#include "device_manager_log.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    constexpr int32_t CLIENT_DATA_BUFFER_LENGTH = 2048;
    const int32_t RECV_DATA_TIMEOUT = 5;
    const int32_t REQUEST_ID_LENGTH = 10;
}

DeviceClientChannel::~DeviceClientChannel()
{
    if (socketFd_ != -1) {
        close(socketFd_);
        socketFd_ = -1;
    }
}

int32_t DeviceClientChannel::Connect(const std::string& ip, short port)
{
    HILOGI("DeviceClientChannel::Connect begin to connect to server.");
    int32_t socketFd = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFd == -1) {
        HILOGE("DeviceClientChannel::Connect create socket failed, errMsg: %{public}s.", strerror(errno));
        return -1;
    }

    struct sockaddr_in addr;
    if (memset_s(&addr, sizeof(addr), 0, sizeof(addr)) != EOK) {
        HILOGE("DeviceClientChannel::Connect error init addr.");
        close(socketFd);
        return -1;
    }
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    addr.sin_port = htons(port);

    int32_t ret = connect(socketFd, (struct sockaddr*) &addr, sizeof(addr));
    if (ret == -1) {
        HILOGE("DeviceClientChannel::Connect connet server failed, errMsg: %{public}s.", strerror(errno));
        close(socketFd);
        return -1;
    }

    socketFd_ = socketFd;
    HILOGI("DeviceClientChannel::Connect connect to server, fd: %{public}d.", socketFd_);

    // wait five seconds, if recv none, release the connection
    struct timeval timeout = {RECV_DATA_TIMEOUT, 0};
    setsockopt(socketFd_, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));
    return 0;
}

bool DeviceClientChannel::Send(const char* data, const int32_t dataLen)
{
    // The client needs to add requestId to the header of the data
    std::stringstream reqIdStr;
    reqIdStr << requestId_;

    int32_t sendDataLen = dataLen + REQUEST_ID_LENGTH;
    std::unique_ptr<char[]> sendData = std::make_unique<char[]>(sendDataLen);
    if (memset_s(sendData.get(), sendDataLen, 0, sendDataLen) != EOK) {
        HILOGE("DeviceClientChannel::Send error init send data.");
        return false;
    }

    if (memcpy_s(sendData.get(), sendDataLen, reqIdStr.str().c_str(), REQUEST_ID_LENGTH) != EOK) {
        HILOGE("DeviceClientChannel::Send error init requestId.");
        return false;
    }

    if (memcpy_s(sendData.get() + REQUEST_ID_LENGTH, sendDataLen - REQUEST_ID_LENGTH, data, dataLen) != EOK) {
        HILOGE("DeviceClientChannel::Send error init data.");
        return false;
    }

    int32_t ret = send(socketFd_, sendData.get(), sendDataLen, 0);
    if (ret == -1) {
        HILOGE("DeviceClientChannel::send data failed, errMsg: %{public}s.", strerror(errno));
        return false;
    }

    HILOGI("DeviceClientChannel::send data, size:%{public}d.", ret);
    return true;
}

void DeviceClientChannel::Receive()
{
    HILOGI("DeviceClientChannel::Receive data, socketFd:%{public}d.", socketFd_);
    char dataBuf[CLIENT_DATA_BUFFER_LENGTH] = {0};

    while (socketFd_ != -1) {
        (void)memset_s(dataBuf, sizeof(dataBuf), 0, sizeof(dataBuf));
        int32_t rc = recv(socketFd_, dataBuf, sizeof(dataBuf), 0);
        if (rc == 0) {
            HILOGE("DeviceClientChannel::Receive error, client shutdown, socketFd_:%{public}d, errMsg: %{public}s.",
                socketFd_, strerror(errno));
            close(socketFd_);
            socketFd_ = -1;
            break;
        } else if (rc == -1 || rc == EAGAIN) {
            HILOGE("DeviceClientChannel::Receive data failed, socketFd_:%{public}d, errMsg: %{public}s.",
                socketFd_, strerror(errno));
            close(socketFd_);
            socketFd_ = -1;
            break;
        } else {
            HILOGI("DeviceClientChannel::Receive data, socketFd_:%{public}d, size:%{public}d.", socketFd_, rc);
            OnDataReceived(dataBuf, rc);
        }
    }
    HILOGI("DeviceClientChannel::Receive data end, socketFd:%{public}d.", socketFd_);
}

void DeviceClientChannel::OnDataReceived(const char* data, const int32_t dataLen)
{
    int ret = deviceGroupManager_.processData(requestId_, (uint8_t *) data, dataLen);
    HILOGI("DeviceClientChannel::OnDataReceived process data, ret:%{public}d, dataLen:%{public}d.", ret, dataLen);
    if (ret != 0) {
        close(socketFd_);
        socketFd_ = -1;
        onError_(requestId_, 0, ret, nullptr);
    }
}

void DeviceClientChannel::ResetConnection()
{
    HILOGI("DeviceClientChannel::ResetConnection bind finished, release connection.");
    close(socketFd_);
    socketFd_ = -1;
}
}
}