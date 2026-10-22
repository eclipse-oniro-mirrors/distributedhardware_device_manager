/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "dm_crypto_3rd_Refactor.h"

#include <iostream>
#include <sstream>
#include <securec.h>
#include <openssl/rand.h>
#include "openssl/sha.h"

#include "dm_log_3rd.h"
#include "datetime_ex.h"

namespace OHOS {
namespace DistributedHardware {

constexpr int32_t HEX_TO_UINT8 = 2;
constexpr int WIDTH = 4;
constexpr unsigned char MASK = 0x0F;
constexpr int DEC_MAX_NUM = 10;
constexpr int HEX_MAX_BIT_NUM = 4;
constexpr uint32_t ERR_DM_FAILED = 96929744;
constexpr int32_t DM_OK = 0;
constexpr int32_t DM_ERR = -1;
constexpr int32_t ERR_DM_INPUT_PARA_INVALID = 96929749;
constexpr int HEX_DIGIT_MAX_NUM = 16;
constexpr int SHORT_DEVICE_ID_HASH_LENGTH = 16;
constexpr int32_t SALT_LENGTH = 8;
constexpr int SHORT_ACCOUNTID_ID_HASH_LENGTH = 6;
constexpr uint32_t DM_MAX_DEVICE_ID_LEN = 97;

static void SecureClearBuffer(void *buf, size_t len)
{
    if (buf == nullptr || len == 0) {
        return;
    }
    (void)memset_s(buf, len, 0, len);
}

static unsigned char ConvertHexCharToValue(char c, bool &valid)
{
    valid = true;
    if (c >= '0' && c <= '9') {
        return static_cast<unsigned char>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<unsigned char>(c - 'a' + DEC_MAX_NUM);
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<unsigned char>(c - 'A' + DEC_MAX_NUM);
    }
    valid = false;
    return 0;
}

static int32_t DoHash(const std::string &input, unsigned char *outBuf, uint32_t outBufLen, uint32_t hexBytes)
{
    if (input.empty() || outBuf == nullptr) {
        LOGE("Invalid parameter.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    Crypto3rdRefactor::DmGenerateStrHash(input.data(), input.size(), hash, SHA256_DIGEST_LENGTH, 0);
    int32_t ret = Crypto3rdRefactor::ConvertBytesToHexString(
        reinterpret_cast<char *>(outBuf), outBufLen,
        reinterpret_cast<const uint8_t *>(hash), hexBytes);
    SecureClearBuffer(hash, sizeof(hash));
    return ret;
}

static std::string DoHashToString(const std::string &input, uint32_t outBufLen, uint32_t hexBytes)
{
    if (input.empty()) {
        LOGE("Invalid parameter, input is empty.");
        return "";
    }
    std::vector<unsigned char> outBuf(outBufLen, 0);
    if (DoHash(input, outBuf.data(), outBufLen, hexBytes) != DM_OK) {
        LOGE("DoHash failed.");
        return "";
    }
    std::string result(reinterpret_cast<char *>(outBuf.data()));
    SecureClearBuffer(outBuf.data(), outBuf.size());
    return result;
}

uint32_t HexifyLen(uint32_t len)
{
    if (len > (UINT32_MAX - 1) / HEX_TO_UINT8) {
        LOGE("len is too long, len = %{public}u", len);
        return 0;
    }
    return len * HEX_TO_UINT8 + 1;
}

void Crypto3rdRefactor::DmGenerateStrHash(const void *data, size_t dataSize,
    unsigned char *outBuf, uint32_t outBufLen, uint32_t startIndex)
{
    if (data == nullptr || outBuf == nullptr || startIndex > outBufLen) {
        LOGE("Invalid param.");
        return;
    }
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, dataSize);
    SHA256_Final(&outBuf[startIndex], &ctx);
    SecureClearBuffer(&ctx, sizeof(ctx));
}

int32_t Crypto3rdRefactor::ConvertBytesToHexString(char *outBuf, uint32_t outBufLen,
    const unsigned char *inBuf, uint32_t inLen)
{
    if (outBuf == nullptr || inBuf == nullptr) {
        return ERR_DM_INPUT_PARA_INVALID;
    }
    if (outBufLen < HexifyLen(inLen)) {
        return ERR_DM_INPUT_PARA_INVALID;
    }
    while (inLen > 0) {
        unsigned char h = *inBuf / HEX_DIGIT_MAX_NUM;
        unsigned char l = *inBuf % HEX_DIGIT_MAX_NUM;
        if (h < DEC_MAX_NUM) {
            *outBuf++ = static_cast<char>('0' + h);
        } else {
            *outBuf++ = static_cast<char>('a' + h - DEC_MAX_NUM);
        }
        if (l < DEC_MAX_NUM) {
            *outBuf++ = static_cast<char>('0' + l);
        } else {
            *outBuf++ = static_cast<char>('a' + l - DEC_MAX_NUM);
        }
        ++inBuf;
        --inLen;
    }
    return DM_OK;
}

std::string Crypto3rdRefactor::Sha256(const std::string &text, bool isUpper)
{
    return Sha256(text.data(), text.size(), isUpper);
}

std::string Crypto3rdRefactor::Sha256(const void *data, size_t size, bool isUpper)
{
    if (data == nullptr || size == 0) {
        return "";
    }
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    DmGenerateStrHash(data, size, hash, SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH);
    std::string result = HashToHexStr(hash, SHA256_DIGEST_LENGTH, isUpper);
    SecureClearBuffer(hash, sizeof(hash));
    return result;
}

int32_t Crypto3rdRefactor::GetUdidHash(const std::string &udid, unsigned char *udidHash)
{
    if (udidHash == nullptr) {
        LOGE("Invalid parameter, udidHash is nullptr.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    uint32_t outBufLen = SHORT_DEVICE_ID_HASH_LENGTH + 1;
    uint32_t hexBytes = SHORT_DEVICE_ID_HASH_LENGTH / HEX_TO_UINT8;
    int32_t ret = DoHash(udid, udidHash, outBufLen, hexBytes);
    if (ret != DM_OK) {
        return ERR_DM_FAILED;
    }
    return DM_OK;
}

std::string Crypto3rdRefactor::GetUdidHash(const std::string &udid)
{
    uint32_t outBufLen = SHORT_DEVICE_ID_HASH_LENGTH + 1;
    uint32_t hexBytes = SHORT_DEVICE_ID_HASH_LENGTH / HEX_TO_UINT8;
    return DoHashToString(udid, outBufLen, hexBytes);
}

std::string Crypto3rdRefactor::GetTokenIdHash(const std::string &tokenId)
{
    uint32_t outBufLen = SHA256_DIGEST_LENGTH + 1;
    uint32_t hexBytes = SHA256_DIGEST_LENGTH / HEX_TO_UINT8;
    return DoHashToString(tokenId, outBufLen, hexBytes);
}

int32_t Crypto3rdRefactor::ConvertHexStringToBytes(unsigned char *outBuf,
    uint32_t outBufLen, const char *inBuf, uint32_t inLen)
{
    if (outBuf == nullptr || inBuf == nullptr) {
        LOGE("invalid param, null pointer.");
        return ERR_DM_FAILED;
    }
    if (inLen % HEX_TO_UINT8 != 0) {
        LOGE("invalid param, inLen is odd.");
        return ERR_DM_FAILED;
    }
    uint32_t outLen = inLen / HEX_TO_UINT8;
    if (outBufLen < outLen) {
        LOGE("out of memory.");
        return ERR_DM_FAILED;
    }
    uint32_t i = 0;
    while (i < outLen) {
        bool valid1 = false;
        unsigned char c1 = ConvertHexCharToValue(*inBuf++, valid1);
        if (!valid1) {
            LOGE("HexToString Error at position 1.");
            return ERR_DM_FAILED;
        }
        bool valid2 = false;
        unsigned char c2 = ConvertHexCharToValue(*inBuf++, valid2);
        if (!valid2) {
            LOGE("HexToString Error at position 2.");
            return ERR_DM_FAILED;
        }
        *outBuf++ = static_cast<unsigned char>((c1 << HEX_MAX_BIT_NUM) | c2);
        ++i;
    }
    return DM_OK;
}
} // namespace DistributedHardware
} // namespace OHOS
