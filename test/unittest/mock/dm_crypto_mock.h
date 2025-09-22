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
#ifndef OHOS_DM_CRYPTO_MOCK_H
#define OHOS_DM_CRYPTO_MOCK_H

#include <string>
#include <gmock/gmock.h>

#include "dm_crypto.h"

namespace OHOS {
namespace DistributedHardware {
class DmCrypto {
public:
    virtual ~DmCrypto() = default;
public:
    virtual int32_t GetAccountIdHash(const std::string &accountId, unsigned char *accountIdHash) = 0;
    virtual int32_t ConvertUdidHashToAnoyAndSave(const std::string &appId, const std::string &udidHash,
        DmKVValue &kvValue) = 0;
    virtual int32_t GetUdidHash(const std::string &udid, unsigned char *udidHash) = 0;
    virtual std::string GetGroupIdHash(const std::string &groupId) = 0;
    virtual int32_t ConvertUdidHashToAnoyDeviceId(const std::string &appId, const std::string &udidHash,
        DmKVValue &kvValue) = 0;
public:
    static inline std::shared_ptr<DmCrypto> dmCrypto = nullptr;
};

class CryptoMock : public DmCrypto {
public:
    MOCK_METHOD(int32_t, GetAccountIdHash, (const std::string &, unsigned char *));
    MOCK_METHOD(int32_t, ConvertUdidHashToAnoyAndSave, (const std::string &, const std::string &, DmKVValue &));
    MOCK_METHOD(int32_t, GetUdidHash, (const std::string &, unsigned char *));
    MOCK_METHOD(std::string, GetGroupIdHash, (const std::string &));
    MOCK_METHOD(int32_t, ConvertUdidHashToAnoyDeviceId, (const std::string &, const std::string &, DmKVValue &));
    MOCK_METHOD(int32_t, RAND_bytes, (unsigned char *, int32_t));
};
}
}
#endif
