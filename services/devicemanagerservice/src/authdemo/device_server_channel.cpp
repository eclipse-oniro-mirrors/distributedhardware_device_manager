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

#include "device_server_channel.h"

#include <cstdlib>
#include <cstring>

#include <errno.h>
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
    const int32_t DATA_BUFFER_LENGTH = 2048;
    const int32_t REQUEST_ID_LENGTH = 10;
    const int32_t LISTENING_QUEUE_LEN = 10;
    const int64_t MIN_REQUEST_ID = 1000000000;
    const int32_t RECV_DATA_TIMEOUT = 5;
}

DeviceServerChannel::~DeviceServerChannel()
{
    if (socketFd_ != -1) {
        close(socketFd_);
        socketFd_ = -1;
    }

    if (clientFd_ != -1) {
        close(clientFd_);
        clientFd_ = -1;
    }
}

int32_t DeviceServerChannel::Start(const int32_t port)
{
    HILOGI("DeviceServerChannel::Start begin to start server.");
    if (port <= 0) {
        HILOGE("DeviceServerChannel::start port is invalid.");
        return -1;
    }

    int32_t socketFd = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFd == -1) {
        HILOGE("DeviceServerChannel::start create socket failed, errMsg: %{public}s.", strerror(errno));
        return -1;
    }

    struct sockaddr_in addr;
    if (memset_s(&addr, sizeof(addr), 0, sizeof(addr)) != EOK) {
        HILOGE("DeviceServerChannel::Start error init addr.");
        close(socketFd);
        return -1;
    }
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    int32_t ret = bind(socketFd, (struct sockaddr*) &addr, sizeof(addr));
    if (ret == -1) {
        HILOGE("DeviceServerChannel::start bind addr failed, errMsg: %{public}s.", strerror(errno));
        close(socketFd);
        return -1;
    }

    socketFd_ = socketFd;
    HILOGI("DeviceServerChannel::start bind addr success, fd:%{public}d.", socketFd_);

    ret = listen(socketFd_, LISTENING_QUEUE_LEN);
    if (ret == -1) {
        HILOGE("DeviceServerChannel::start listen port failed, errMsg: %{public}s.", strerror(errno));
        close(socketFd_);
        socketFd_ = -1;
        return -1;
    }

    return 0;
}

void DeviceServerChannel::Receive()
{
    HILOGI("DeviceServerChannel::receive begin to listen client connecting.");
    struct sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);

    while (true) {
        int32_t fd = accept(socketFd_, (struct sockaddr*) &client_addr, &len);
        if (fd == -1) {
            HILOGE("DeviceServerChannel::receive accept connect failed, errMsg: %{public}s.", strerror(errno));
            continue;
        }

        if (clientFd_ != -1) {
            HILOGW("DeviceServerChannel::receive another client is connected, close new connect.");
            close(fd);
            continue;
        }

        HILOGI("DeviceServerChannel::receive new client in.");
        clientFd_ = fd;

        // wait five seconds, if recv none, release the connection
        struct timeval timeout = {RECV_DATA_TIMEOUT, 0};
        setsockopt(clientFd_, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

        // demo project, blocked here to receive data, informal solution, will be discard later
        char dataBuf[DATA_BUFFER_LENGTH] = {0};
        while (clientFd_ != -1) {
            if (memset_s(dataBuf, sizeof(dataBuf), 0, sizeof(dataBuf)) != EOK) {
                HILOGE("DeviceServerChannel::receive error init data buf.");
                close(clientFd_);
                clientFd_ = -1;
                break;
            }

            int32_t rc = recv(clientFd_, dataBuf, sizeof(dataBuf), 0);
            if (rc == 0) {
                HILOGE("DeviceServerChannel::receive error, client shutdown.");
                close(clientFd_);
                clientFd_ = -1;
                break;
            } else if (rc == -1 || rc == EAGAIN) {
                HILOGE("DeviceServerChannel::receive receive data failed, errMsg: %{public}s.", strerror(errno));
                close(clientFd_);
                clientFd_ = -1;
                break;
            } else {
                HILOGI("DeviceServerChannel::receive receive data, size:%{public}d.", rc);
                OnDataReceived(dataBuf, rc);
            }
        }
    }
}

void DeviceServerChannel::OnDataReceived(const char* data, const int32_t dataLen)
{
    HILOGI("DeviceServerChannel::OnDataReceived dataLen:%{public}d.", dataLen);
    if (dataLen < REQUEST_ID_LENGTH) {
        HILOGI("DeviceServerChannel::OnDataReceived error, data is invalid.");
        return;
    }

    // the client adds requestId to the header of data, the server needs to parse the original data
    char reqIdChar[REQUEST_ID_LENGTH + 1] = {0};
    (void)memcpy_s(reqIdChar, sizeof(reqIdChar), data, REQUEST_ID_LENGTH);
    reqIdChar[REQUEST_ID_LENGTH] = '\0';
    int64_t requestId = strtoll(reqIdChar, nullptr, REQUEST_ID_LENGTH);
    if (requestId < MIN_REQUEST_ID) {
        HILOGI("DeviceServerChannel::OnDataReceived error, requestId is invalid.");
        return;
    }

    const char* newData = data + REQUEST_ID_LENGTH;
    int len = dataLen - REQUEST_ID_LENGTH;
    int ret = deviceGroupManager_.processData(requestId, (const uint8_t *) newData, len);
    HILOGI("DeviceServerChannel::OnDataReceived process data, ret:%{public}d, dataLen:%{public}d.", ret, len);
    if (ret != 0) {
        onError_(requestId, 0, ret, nullptr);
        close(clientFd_);
        clientFd_ = -1;
    }
}

bool DeviceServerChannel::Send(const char* data, const int32_t dataLen)
{
    int32_t ret = send(clientFd_, data, dataLen, 0);
    if (ret == -1) {
        HILOGE("DeviceServerChannel::send failed,socket:%{public}d,errMsg: %{public}s.", clientFd_, strerror(errno));
        return false;
    }

    HILOGI("DeviceServerChannel::send data,socket:%{public}d, size:%{public}d.", clientFd_, ret);
    return true;
}

void DeviceServerChannel::ResetConnection()
{
    HILOGI("DeviceServerChannel::ResetConnection bind finished, release connection.");
    close(clientFd_);
    clientFd_ = -1;
}
}
}