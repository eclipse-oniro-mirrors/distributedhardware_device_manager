/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_HICHAIN_AUTH_CONNECTOR_MOCK_H
#define OHOS_HICHAIN_AUTH_CONNECTOR_MOCK_H

#include <string>
#include <gmock/gmock.h>

#include "hichain_auth_connector.h"

namespace OHOS {
namespace DistributedHardware {
class DmHiChainAuthConnector {
public:
    virtual ~DmHiChainAuthConnector() = default;
public:
    virtual bool QueryCredential(std::string &localUdid, int32_t osAccountId, int32_t peerOsAccountId) = 0;
    virtual int32_t AuthDevice(int32_t pinCode, int32_t osAccountId, std::string udid, int64_t requestId) = 0;
    virtual int32_t ImportCredential(int32_t osAccountId, int32_t peerOsAccountId, std::string deviceId,
        std::string publicKey) = 0;
public:
    static inline std::shared_ptr<DmHiChainAuthConnector> dmHiChainAuthConnector = nullptr;
};

class HiChainAuthConnectorMock : public DmHiChainAuthConnector {
public:
    MOCK_METHOD(bool, QueryCredential, (std::string &, int32_t, int32_t));
    MOCK_METHOD(int32_t, AuthDevice, (int32_t, int32_t, std::string, int64_t));
    MOCK_METHOD(int32_t, ImportCredential, (int32_t, int32_t, std::string, std::string));
};
}
}
#endif
