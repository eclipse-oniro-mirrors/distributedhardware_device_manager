/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "UTTest_dm_crypto.h"

#include <cinttypes>
#include <iostream>

#include "dm_constants.h"
#include "dm_crypto.h"
#include <openssl/sha.h>

namespace OHOS {
namespace DistributedHardware {
namespace {
    constexpr int32_t SALT_STRING_LENGTH = 16;
    constexpr int32_t SHA256_HEX_LEN = 64; // SHA256_DIGEST_LENGTH(32) * 2
    const std::string SALT_DEFAULT = "salt_defsalt_def";
    const std::string UDID_SAMPLE = "3fde738fb2b8c910023d949166125bc9ed49e9e2fc8f4826d652b2839def2238";
}
void DmCryptoTest::SetUp()
{
}
void DmCryptoTest::TearDown()
{
}
void DmCryptoTest::SetUpTestCase()
{
}
void DmCryptoTest::TearDownTestCase()
{
}

/**
 * @tc.name: GetSecRandom_01
 * @tc.type: FUNC
 */
HWTEST_F(DmCryptoTest, GetSecRandom_01, testing::ext::TestSize.Level1)
{
    const size_t len = 8;
    uint8_t buffer[len] = {0};
    int32_t ret = Crypto::GetSecRandom(buffer, len);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: GetSecSalt_01
 * @tc.type: FUNC
 */
HWTEST_F(DmCryptoTest, GetSecSalt_01, testing::ext::TestSize.Level1)
{
    std::string salt = Crypto::GetSecSalt();
    EXPECT_EQ(salt.length(), SALT_STRING_LENGTH);
    EXPECT_NE(salt, SALT_DEFAULT);

    std::cout << "Random Salt: " << salt << std::endl;
}

/**
 * @tc.name: GetUdidHash_01
 * @tc.type: FUNC
 */
HWTEST_F(DmCryptoTest, GetUdidHash_01, testing::ext::TestSize.Level1)
{
    char udidHash[DEVICE_UUID_LENGTH] = {0};
    EXPECT_EQ(Crypto::GetUdidHash(UDID_SAMPLE, reinterpret_cast<uint8_t *>(udidHash)), DM_OK);

    std::string res(udidHash);
    std::cout << "udidHash sample: " << res << std::endl;
}

/**
 * @tc.name: GetHashWithSalt_01
 * @tc.type: FUNC
 */
HWTEST_F(DmCryptoTest, GetHashWithSalt_01, testing::ext::TestSize.Level1)
{
    std::string text1 = "c9ed49e9e2fc8f4826d652b2839d";
    std::string text2 = "aaadfasdfasdfc9ed49e9e2sadfasdffc8f4826d6asdfasdf52basdf2839d";
    std::string salt1 = Crypto::GetSecSalt();
    std::string salt2 = Crypto::GetSecSalt();

    std::string hash1 = Crypto::GetHashWithSalt(text1, salt1);
    std::string hash2 = Crypto::GetHashWithSalt(text1, salt2);

    EXPECT_STRNE(hash1.c_str(), hash2.c_str());
    std::cout << "hash1: " << hash1 << std::endl;
    std::cout << "hash2: " << hash2 << std::endl;

    std::string hash3 = Crypto::GetHashWithSalt(text1, salt1);
    std::string hash4 = Crypto::GetHashWithSalt(text2, salt1);
    EXPECT_STRNE(hash3.c_str(), hash4.c_str());
    std::cout << "hash1: " << hash3 << std::endl;
    std::cout << "hash2: " << hash4 << std::endl;

    std::string hash5 = Crypto::GetHashWithSalt(text2, salt1);
    EXPECT_STREQ(hash5.c_str(), hash4.c_str());
    std::cout << "hash5: " << hash5 << std::endl;
    std::cout << "hash4: " << hash4 << std::endl;

    std::string hash6 = Crypto::GetHashWithSalt(text1, salt2);
    EXPECT_STREQ(hash2.c_str(), hash6.c_str());

    std::cout << "hash2: " << hash2 << std::endl;
    std::cout << "hash6: " << hash6 << std::endl;
}

/**
 * @tc.name: GetSecRandom_02
 * @tc.type: FUNC
 */
HWTEST_F(DmCryptoTest, GetSecRandom_02, testing::ext::TestSize.Level1)
{
    // null out buffer -> DM_ERR early return
    int32_t ret = Crypto::GetSecRandom(nullptr, 8);
    EXPECT_EQ(ret, -1);

    // zero length -> DM_ERR early return
    uint8_t buffer[8] = {0};
    ret = Crypto::GetSecRandom(buffer, 0);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: Sha256_01
 * @tc.type: FUNC
 */
HWTEST_F(DmCryptoTest, Sha256_01, testing::ext::TestSize.Level1)
{
    // string overload default lowercase
    std::string text = "c9ed49e9e2fc8f4826d652b2839d";
    std::string hashLower = Crypto::Sha256(text);
    EXPECT_EQ(hashLower.length(), static_cast<size_t>(SHA256_HEX_LEN));

    // uppercase path (isUpper = true)
    std::string hashUpper = Crypto::Sha256(text, true);
    EXPECT_EQ(hashUpper.length(), static_cast<size_t>(SHA256_HEX_LEN));
    EXPECT_STRNE(hashLower.c_str(), hashUpper.c_str());

    // void* overload
    std::string hashVoid = Crypto::Sha256(text.data(), text.size());
    EXPECT_STREQ(hashLower.c_str(), hashVoid.c_str());
}

/**
 * @tc.name: ConvertHexStringToBytes_01
 * @tc.type: FUNC
 */
HWTEST_F(DmCryptoTest, ConvertHexStringToBytes_01, testing::ext::TestSize.Level1)
{
    // null outBuf -> ERR_DM_FAILED
    const char *hexIn = "1a2b";
    int32_t ret = Crypto::ConvertHexStringToBytes(nullptr, 4, hexIn, 4);
    EXPECT_EQ(ret, ERR_DM_FAILED);

    // null inBuf -> ERR_DM_FAILED
    uint8_t out[2] = {0};
    ret = Crypto::ConvertHexStringToBytes(out, 2, nullptr, 4);
    EXPECT_EQ(ret, ERR_DM_FAILED);

    // odd length -> ERR_DM_FAILED
    ret = Crypto::ConvertHexStringToBytes(out, 2, hexIn, 3);
    EXPECT_EQ(ret, ERR_DM_FAILED);
}

/**
 * @tc.name: ConvertHexStringToBytes_02
 * @tc.type: FUNC
 */
HWTEST_F(DmCryptoTest, ConvertHexStringToBytes_02, testing::ext::TestSize.Level1)
{
    // outBufLen smaller than outLen -> ERR_DM_FAILED
    const char *hexIn = "1a2b";
    uint8_t out[1] = {0};
    int32_t ret = Crypto::ConvertHexStringToBytes(out, 1, hexIn, 4);
    EXPECT_EQ(ret, ERR_DM_FAILED);
}

/**
 * @tc.name: ConvertHexStringToBytes_03
 * @tc.type: FUNC
 */
HWTEST_F(DmCryptoTest, ConvertHexStringToBytes_03, testing::ext::TestSize.Level1)
{
    // valid lowercase hex -> DM_OK
    const char *hexLower = "1a2b";
    uint8_t out[2] = {0};
    int32_t ret = Crypto::ConvertHexStringToBytes(out, 2, hexLower, 4);
    EXPECT_EQ(ret, DM_OK);
    EXPECT_EQ(out[0], 0x1a);
    EXPECT_EQ(out[1], 0x2b);

    // valid uppercase hex path -> DM_OK (even length exercises 'A'-'F' branch)
    const char *hexUpper = "0F1A";
    uint8_t out2[2] = {0};
    ret = Crypto::ConvertHexStringToBytes(out2, 2, hexUpper, 4);
    EXPECT_EQ(ret, DM_OK);
    EXPECT_EQ(out2[0], 0x0f);
    EXPECT_EQ(out2[1], 0x1a);

    // invalid char -> ERR_DM_FAILED
    const char *hexInvalid = "1g2b";
    uint8_t out3[2] = {0};
    ret = Crypto::ConvertHexStringToBytes(out3, 2, hexInvalid, 4);
    EXPECT_EQ(ret, ERR_DM_FAILED);
}

/**
 * @tc.name: ConvertBytesToHexString_01
 * @tc.type: FUNC
 */
HWTEST_F(DmCryptoTest, ConvertBytesToHexString_01, testing::ext::TestSize.Level1)
{
    // null outBuf -> ERR_DM_INPUT_PARA_INVALID
    unsigned char in[2] = {0x1a, 0xff};
    int32_t ret = Crypto::ConvertBytesToHexString(nullptr, 8, in, 2);
    EXPECT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);

    // null inBuf -> ERR_DM_INPUT_PARA_INVALID
    char out[5] = {0};
    ret = Crypto::ConvertBytesToHexString(out, 5, nullptr, 2);
    EXPECT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);

    // outBufLen too small -> ERR_DM_INPUT_PARA_INVALID
    ret = Crypto::ConvertBytesToHexString(out, 2, in, 2);
    EXPECT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: ConvertBytesToHexString_02
 * @tc.type: FUNC
 */
HWTEST_F(DmCryptoTest, ConvertBytesToHexString_02, testing::ext::TestSize.Level1)
{
    // valid conversion covering digit(<10) and letter(>=10) branches
    unsigned char in[2] = {0x1a, 0xff};
    char out[5] = {0};
    int32_t ret = Crypto::ConvertBytesToHexString(out, 5, in, 2);
    EXPECT_EQ(ret, DM_OK);
    EXPECT_STREQ(out, "1aff");

    // value entirely below 10
    unsigned char in2[1] = {0x09};
    char out2[3] = {0};
    ret = Crypto::ConvertBytesToHexString(out2, 3, in2, 1);
    EXPECT_EQ(ret, DM_OK);
    EXPECT_STREQ(out2, "09");
}

/**
 * @tc.name: GetUdidHash_02
 * @tc.type: FUNC
 */
HWTEST_F(DmCryptoTest, GetUdidHash_02, testing::ext::TestSize.Level1)
{
    // string overload returns 16-char short hash
    std::string hash = Crypto::GetUdidHash(UDID_SAMPLE);
    EXPECT_EQ(hash.length(), static_cast<size_t>(16));
    std::cout << "udidHash string: " << hash << std::endl;
}

/**
 * @tc.name: GetTokenIdHash_01
 * @tc.type: FUNC
 */
HWTEST_F(DmCryptoTest, GetTokenIdHash_01, testing::ext::TestSize.Level1)
{
    std::string tokenId = "token123456";
    std::string hash = Crypto::GetTokenIdHash(tokenId);
    EXPECT_EQ(hash.length(), static_cast<size_t>(32));
    std::cout << "tokenIdHash: " << hash << std::endl;
}

/**
 * @tc.name: GetGroupIdHash_01
 * @tc.type: FUNC
 */
HWTEST_F(DmCryptoTest, GetGroupIdHash_01, testing::ext::TestSize.Level1)
{
    std::string groupId = "groupTestId";
    std::string hash = Crypto::GetGroupIdHash(groupId);
    EXPECT_EQ(hash.length(), static_cast<size_t>(16));
    std::cout << "groupIdHash: " << hash << std::endl;
}

/**
 * @tc.name: GetAccountIdHash_01
 * @tc.type: FUNC
 */
HWTEST_F(DmCryptoTest, GetAccountIdHash_01, testing::ext::TestSize.Level1)
{
    std::string accountId = "accountIdTest";
    // int32_t overload returns first 3 bytes (6 chars)
    unsigned char hash[7] = {0};
    int32_t ret = Crypto::GetAccountIdHash(accountId, hash);
    EXPECT_EQ(ret, DM_OK);
    std::string hashStr(reinterpret_cast<const char *>(hash));
    EXPECT_EQ(hashStr.length(), static_cast<size_t>(6));

    // string overload returns first 16 bytes (32 chars)
    std::string hash16 = Crypto::GetAccountIdHash16(accountId);
    EXPECT_EQ(hash16.length(), static_cast<size_t>(32));
}

/**
 * @tc.name: GetAccountIdHash7_01
 * @tc.type: FUNC
 * @tc.desc: Normal case - GetAccountIdHash7 returns DM_OK and 7-char hash
 */
HWTEST_F(DmCryptoTest, GetAccountIdHash7_01, testing::ext::TestSize.Level1)
{
    std::string accountId = "accountIdTest7";
    unsigned char hash[8] = {0};
    int32_t ret = Crypto::GetAccountIdHash7(accountId, hash);
    EXPECT_EQ(ret, DM_OK);
    std::string hashStr(reinterpret_cast<const char *>(hash));
    EXPECT_EQ(hashStr.length(), static_cast<size_t>(7));
    std::cout << "accountIdHash7: " << hashStr << std::endl;
}

/**
 * @tc.name: GetAccountIdHash7_02
 * @tc.type: FUNC
 * @tc.desc: Different accountIds produce different hash7 values
 */
HWTEST_F(DmCryptoTest, GetAccountIdHash7_02, testing::ext::TestSize.Level1)
{
    unsigned char hash1[8] = {0};
    unsigned char hash2[8] = {0};
    Crypto::GetAccountIdHash7("accountA", hash1);
    Crypto::GetAccountIdHash7("accountB", hash2);
    std::string str1(reinterpret_cast<const char *>(hash1));
    std::string str2(reinterpret_cast<const char *>(hash2));
    EXPECT_STRNE(str1.c_str(), str2.c_str());
}

/**
 * @tc.name: GetAccountIdHash7_03
 * @tc.type: FUNC
 * @tc.desc: Same accountId produces same hash7 (deterministic)
 */
HWTEST_F(DmCryptoTest, GetAccountIdHash7_03, testing::ext::TestSize.Level1)
{
    unsigned char hash1[8] = {0};
    unsigned char hash2[8] = {0};
    Crypto::GetAccountIdHash7("sameAccount", hash1);
    Crypto::GetAccountIdHash7("sameAccount", hash2);
    std::string str1(reinterpret_cast<const char *>(hash1));
    std::string str2(reinterpret_cast<const char *>(hash2));
    EXPECT_STREQ(str1.c_str(), str2.c_str());
}

/**
 * @tc.name: DmGenerateStrHash_01
 * @tc.type: FUNC
 * @tc.desc: Null data param - early return without crash
 */
HWTEST_F(DmCryptoTest, DmGenerateStrHash_01, testing::ext::TestSize.Level1)
{
    unsigned char outBuf[SHA256_DIGEST_LENGTH] = {0};
    Crypto::DmGenerateStrHash(nullptr, 32, outBuf, SHA256_DIGEST_LENGTH, 0);
    bool unchanged = true;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        if (outBuf[i] != 0) {
            unchanged = false;
            break;
        }
    }
    EXPECT_TRUE(unchanged);
}

/**
 * @tc.name: DmGenerateStrHash_02
 * @tc.type: FUNC
 * @tc.desc: Null outBuf param - early return without crash
 */
HWTEST_F(DmCryptoTest, DmGenerateStrHash_02, testing::ext::TestSize.Level1)
{
    std::string text = "testData";
    Crypto::DmGenerateStrHash(text.data(), text.size(), nullptr, SHA256_DIGEST_LENGTH, 0);
    EXPECT_TRUE(true);
}

/**
 * @tc.name: DmGenerateStrHash_03
 * @tc.type: FUNC
 * @tc.desc: startIndex > outBufLen - early return without crash, outBuf unchanged
 */
HWTEST_F(DmCryptoTest, DmGenerateStrHash_03, testing::ext::TestSize.Level1)
{
    std::string text = "testData";
    unsigned char outBuf[SHA256_DIGEST_LENGTH] = {0};
    const uint32_t outBufLen = SHA256_DIGEST_LENGTH;
    const uint32_t invalidStartIndex = outBufLen + 1;
    Crypto::DmGenerateStrHash(text.data(), text.size(), outBuf, outBufLen, invalidStartIndex);
    bool unchanged = true;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        if (outBuf[i] != 0) {
            unchanged = false;
            break;
        }
    }
    EXPECT_TRUE(unchanged);
}

/**
 * @tc.name: DmGenerateStrHash_004
 * @tc.type: FUNC
 * @tc.desc: Normal case - hash is written to outBuf at startIndex offset
 */
HWTEST_F(DmCryptoTest, DmGenerateStrHash_004, testing::ext::TestSize.Level1)
{
    std::string text = "hello";
    unsigned char hash[SHA256_DIGEST_LENGTH * 2] = {0};
    Crypto::DmGenerateStrHash(text.data(), text.size(), hash, sizeof(hash), SHA256_DIGEST_LENGTH);
    bool allZero = true;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        if (hash[SHA256_DIGEST_LENGTH + i] != 0) {
            allZero = false;
            break;
        }
    }
    EXPECT_FALSE(allZero);
}

/**
 * @tc.name: ConvertHexStringToBytes_004
 * @tc.type: FUNC
 * @tc.desc: Invalid char in second position (c2) -> ERR_DM_FAILED
 */
HWTEST_F(DmCryptoTest, ConvertHexStringToBytes_004, testing::ext::TestSize.Level1)
{
    const char *hexInvalidC2 = "1g";
    uint8_t out[1] = {0};
    int32_t ret = Crypto::ConvertHexStringToBytes(out, 1, hexInvalidC2, 2);
    EXPECT_EQ(ret, ERR_DM_FAILED);
}

/**
 * @tc.name: ConvertHexStringToBytes_005
 * @tc.type: FUNC
 * @tc.desc: Valid mixed-case hex with letters in both positions -> DM_OK
 */
HWTEST_F(DmCryptoTest, ConvertHexStringToBytes_005, testing::ext::TestSize.Level1)
{
    const char *hexMixed = "Af";
    uint8_t out[1] = {0};
    int32_t ret = Crypto::ConvertHexStringToBytes(out, 1, hexMixed, 2);
    EXPECT_EQ(ret, DM_OK);
    EXPECT_EQ(out[0], 0xAF);
}

/**
 * @tc.name: ConvertBytesToHexString_003
 * @tc.type: FUNC
 * @tc.desc: Zero-length input (inLen=0) -> DM_OK with empty output
 */
HWTEST_F(DmCryptoTest, ConvertBytesToHexString_003, testing::ext::TestSize.Level1)
{
    unsigned char in[1] = {0x00};
    char out[1] = {0};
    int32_t ret = Crypto::ConvertBytesToHexString(out, 1, in, 0);
    EXPECT_EQ(ret, DM_OK);
}

/**
 * @tc.name: ConvertBytesToHexString_004
 * @tc.type: FUNC
 * @tc.desc: Value exactly at DEC_MAX_NUM boundary (0x0A) -> letter branch
 */
HWTEST_F(DmCryptoTest, ConvertBytesToHexString_004, testing::ext::TestSize.Level1)
{
    unsigned char in[1] = {0x0A};
    char out[3] = {0};
    int32_t ret = Crypto::ConvertBytesToHexString(out, 3, in, 1);
    EXPECT_EQ(ret, DM_OK);
    EXPECT_STREQ(out, "0a");
}

/**
 * @tc.name: GetUdidHash_03
 * @tc.type: FUNC
 * @tc.desc: int32_t overload with empty udid - should still return DM_OK
 */
HWTEST_F(DmCryptoTest, GetUdidHash_03, testing::ext::TestSize.Level1)
{
    char udidHash[DEVICE_UUID_LENGTH] = {0};
    int32_t ret = Crypto::GetUdidHash("", reinterpret_cast<uint8_t *>(udidHash));
    EXPECT_EQ(ret, DM_OK);
}

/**
 * @tc.name: GetHashWithSalt_02
 * @tc.type: FUNC
 * @tc.desc: Empty text with salt - should return valid hash
 */
HWTEST_F(DmCryptoTest, GetHashWithSalt_02, testing::ext::TestSize.Level1)
{
    std::string salt = Crypto::GetSecSalt();
    std::string hash = Crypto::GetHashWithSalt("", salt);
    EXPECT_EQ(hash.length(), static_cast<size_t>(SHA256_HEX_LEN));
}

/**
 * @tc.name: Sha256_02
 * @tc.type: FUNC
 * @tc.desc: Empty string input - should return 64-char hash
 */
HWTEST_F(DmCryptoTest, Sha256_02, testing::ext::TestSize.Level1)
{
    std::string hash = Crypto::Sha256("");
    EXPECT_EQ(hash.length(), static_cast<size_t>(SHA256_HEX_LEN));
    std::string hashUpper = Crypto::Sha256("", true);
    EXPECT_EQ(hashUpper.length(), static_cast<size_t>(SHA256_HEX_LEN));
}
} // DistributedHardware
} // OHOS
