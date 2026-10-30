/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_DM_CRYPTO_MGR_3RD_REFACTOR_H
#define OHOS_DM_CRYPTO_MGR_3RD_REFACTOR_H

#include <cinttypes>
#include <cstdint>
#include <string>
#include <vector>

#include "ffrt.h"

namespace OHOS {
namespace DistributedHardware {

constexpr uint32_t SESSION_KEY_LENGTH = 32;
constexpr uint32_t GCM_IV_LEN_REF = 12;

struct DMSessionKeyRefactor {
    uint8_t *key = nullptr;
    uint32_t keyLen = 0;
};

struct AesGcmCipherKeyRefactor {
    uint32_t keyLen = 0;
    unsigned char key[SESSION_KEY_LENGTH] = {0};
    unsigned char iv[GCM_IV_LEN_REF] = {0};
};

class CryptoMgr3rdRefactor {
public:
    CryptoMgr3rdRefactor();
    ~CryptoMgr3rdRefactor();
    int32_t EncryptMessage(const std::string &inputMsg, std::string &outputMsg);
    int32_t DecryptMessage(const std::string &inputMsg, std::string &outputMsg);
    int32_t ProcessSessionKey(const uint8_t *sessionKey, const uint32_t keyLen);
    void ClearSessionKey();
    std::vector<unsigned char> GetSessionKey();

private:
    int32_t DoEncryptData(AesGcmCipherKeyRefactor *cipherKey, const unsigned char *input,
        uint32_t inLen, unsigned char *encryptData, uint32_t *encryptLen);
    int32_t GenerateRandomArray(unsigned char *randStr, uint32_t len);
    int32_t MbedAesGcmEncrypt(const AesGcmCipherKeyRefactor *cipherKey,
        const unsigned char *plainText, uint32_t plainTextSize,
        unsigned char *cipherText, uint32_t cipherTextLen);
    int32_t DoDecryptData(AesGcmCipherKeyRefactor *cipherKey, const unsigned char *input,
        uint32_t inLen, unsigned char *decryptData, uint32_t *decryptLen);
    int32_t MbedAesGcmDecrypt(const AesGcmCipherKeyRefactor *cipherKey,
        const unsigned char *cipherText, uint32_t cipherTextSize,
        unsigned char *plain, uint32_t &plainLen);
    int32_t EncryptToHexOutput(const AesGcmCipherKeyRefactor &cipherKey,
        const std::string &inputMsg, std::string &outputMsg);
    int32_t DecryptFromHexInput(const AesGcmCipherKeyRefactor &cipherKey,
        const std::string &inputMsg, std::string &outputMsg);

private:
    ffrt::mutex sessionKeyMtx_;
    DMSessionKeyRefactor sessionKey_;
    ffrt::mutex randomLock_;
};

} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_CRYPTO_MGR_3RD_REFACTOR_H
