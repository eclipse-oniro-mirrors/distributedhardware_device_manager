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

#include "crypto_mgr_3rd_Refactor.h"

#include <atomic>
#include <cstdlib>
#include <string>

#include "mbedtls/base64.h"
#include "mbedtls/cipher.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/platform.h"
#include "securec.h"
#include "dm_error_type_3rd.h"
#include "dm_crypto_3rd.h"
#include "dm_log_3rd.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
constexpr uint32_t MAX_SESSION_KEY_LENGTH = 512;
constexpr uint32_t TAG_LEN = 16;
constexpr uint32_t OVERHEAD_LEN = GCM_IV_LEN_REF + TAG_LEN;
constexpr uint32_t MAX_ENCRY_MSG_LEN = 10 * 1024 * 1024;
constexpr uint32_t KEY_BITS_UNIT = 8;
constexpr uint32_t HEX_TO_UINT8 = 2;
}

CryptoMgr3rdRefactor::CryptoMgr3rdRefactor()
{
    LOGI("CryptoMgr3rdRefactor ctor");
}
CryptoMgr3rdRefactor::~CryptoMgr3rdRefactor()
{
    LOGI("CryptoMgr3rdRefactor dtor");
    ClearSessionKey();
}
static void SecureClearCipherKey(AesGcmCipherKeyRefactor &cipherKey)
{
    if (memset_s(&cipherKey, sizeof(AesGcmCipherKeyRefactor), 0,
        sizeof(AesGcmCipherKeyRefactor)) != DM_OK) {
        LOGE("memset_s cipherKey failed.");
    }
}

int32_t CryptoMgr3rdRefactor::EncryptMessage(const std::string &inputMsg,
    std::string &outputMsg)
{
    if (inputMsg.length() > MAX_ENCRY_MSG_LEN) {
        LOGE("Encrypt msg too long, size: %{public}zu", inputMsg.size());
        return ERR_DM_CRYPTO_PARA_INVALID;
    }
    std::lock_guard<ffrt::mutex> lock(sessionKeyMtx_);
    AesGcmCipherKeyRefactor cipherKey {};
    cipherKey.keyLen = sessionKey_.keyLen;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH,
        sessionKey_.key, sessionKey_.keyLen) != EOK) {
        LOGE("set key failed.");
        return ERR_DM_CRYPTO_OPT_FAILED;
    }
    int32_t ret = EncryptToHexOutput(cipherKey, inputMsg, outputMsg);
    SecureClearCipherKey(cipherKey);
    return ret;
}
//LCOV_EXCL_STOP
int32_t CryptoMgr3rdRefactor::DoEncryptData(AesGcmCipherKeyRefactor *cipherKey,
    const unsigned char *input, uint32_t inLen,
    unsigned char *encryptData, uint32_t *encryptLen)
{
    if (cipherKey == nullptr || input == nullptr || inLen == 0) {
        return ERR_DM_CRYPTO_PARA_INVALID;
    }
    if (encryptData == nullptr || encryptLen == nullptr) {
        return ERR_DM_CRYPTO_PARA_INVALID;
    }
    if (GenerateRandomArray(cipherKey->iv, sizeof(cipherKey->iv)) != DM_OK) {
        LOGE("generate random iv error.");
        return ERR_DM_CRYPTO_OPT_FAILED;
    }
    uint32_t outLen = inLen + OVERHEAD_LEN;
    int32_t result = MbedAesGcmEncrypt(cipherKey, input, inLen, encryptData, outLen);
    if (result <= 0) {
        return ERR_DM_CRYPTO_OPT_FAILED;
    }
    *encryptLen = static_cast<uint32_t>(result);
    return DM_OK;
}
int32_t CryptoMgr3rdRefactor::MbedAesGcmEncrypt(const AesGcmCipherKeyRefactor *cipherKey,
    const unsigned char *plainText, uint32_t plainTextSize,
    unsigned char *cipherText, uint32_t cipherTextLen)
{
    if (cipherKey == nullptr || plainText == nullptr || plainTextSize == 0) {
        LOGE("Encrypt invalid para.");
        return ERR_DM_CRYPTO_PARA_INVALID;
    }
    if (cipherText == nullptr || cipherTextLen < plainTextSize + OVERHEAD_LEN) {
        LOGE("Encrypt invalid para.");
        return ERR_DM_CRYPTO_PARA_INVALID;
    }
    unsigned char tagBuf[TAG_LEN] = {0};
    mbedtls_gcm_context aesContext;
    mbedtls_gcm_init(&aesContext);
    int32_t ret = mbedtls_gcm_setkey(&aesContext, MBEDTLS_CIPHER_ID_AES,
        cipherKey->key, cipherKey->keyLen * KEY_BITS_UNIT);
    if (ret != 0) {
        mbedtls_gcm_free(&aesContext);
        return ERR_DM_CRYPTO_OPT_FAILED;
    }
    ret = mbedtls_gcm_crypt_and_tag(&aesContext, MBEDTLS_GCM_ENCRYPT,
        plainTextSize, cipherKey->iv, GCM_IV_LEN_REF,
        nullptr, 0, plainText, cipherText + GCM_IV_LEN_REF, TAG_LEN, tagBuf);
    if (ret != 0) {
        mbedtls_gcm_free(&aesContext);
        return ERR_DM_CRYPTO_OPT_FAILED;
    }
    if (memcpy_s(cipherText, cipherTextLen,
        cipherKey->iv, GCM_IV_LEN_REF) != EOK) {
        mbedtls_gcm_free(&aesContext);
        return ERR_DM_CRYPTO_OPT_FAILED;
    }
    uint32_t tagOffset = GCM_IV_LEN_REF + plainTextSize;
    uint32_t tagRemain = cipherTextLen - tagOffset;
    if (memcpy_s(cipherText + tagOffset, tagRemain, tagBuf, TAG_LEN) != 0) {
        mbedtls_gcm_free(&aesContext);
        return ERR_DM_CRYPTO_OPT_FAILED;
    }
    mbedtls_gcm_free(&aesContext);
    return static_cast<int32_t>(plainTextSize + OVERHEAD_LEN);
}
int32_t CryptoMgr3rdRefactor::GenerateRandomArray(unsigned char *randStr, uint32_t len)
{
    if (randStr == nullptr || len == 0) {
        return ERR_DM_CRYPTO_PARA_INVALID;
    }
    static mbedtls_entropy_context entropy;
    static mbedtls_ctr_drbg_context ctrDrbg;
    static std::atomic<bool> initFlag(false);
    if (!initFlag) {
        std::lock_guard<ffrt::mutex> lock(randomLock_);
        if (!initFlag) {
            mbedtls_ctr_drbg_init(&ctrDrbg);
            mbedtls_entropy_init(&entropy);
            int32_t ret = mbedtls_ctr_drbg_seed(
                &ctrDrbg, mbedtls_entropy_func, &entropy, nullptr, 0);
            if (ret != 0) {
                LOGE("gen random seed error, ret=%{public}d", ret);
                return ERR_DM_CRYPTO_OPT_FAILED;
            }
            initFlag = true;
        }
    }
    std::lock_guard<ffrt::mutex> lock(randomLock_);
    int32_t ret = mbedtls_ctr_drbg_random(&ctrDrbg, randStr, len);
    if (ret != 0) {
        LOGE("gen random error, ret=%{public}d", ret);
        return ERR_DM_CRYPTO_OPT_FAILED;
    }
    return DM_OK;
}

int32_t CryptoMgr3rdRefactor::DecryptMessage(const std::string &inputMsg,
    std::string &outputMsg)
{
    std::lock_guard<ffrt::mutex> lock(sessionKeyMtx_);
    AesGcmCipherKeyRefactor cipherKey {};
    cipherKey.keyLen = sessionKey_.keyLen;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH,
        sessionKey_.key, sessionKey_.keyLen) != EOK) {
        LOGE("set key failed.");
        return ERR_DM_CRYPTO_OPT_FAILED;
    }
    int32_t ret = DecryptFromHexInput(cipherKey, inputMsg, outputMsg);
    SecureClearCipherKey(cipherKey);
    return ret;
}
} // namespace DistributedHardware
} // namespace OHOS
