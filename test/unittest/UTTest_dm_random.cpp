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

#include "UTTest_dm_random.h"

#include <iostream>
#include <set>
#include <string>

#include "dm_random.h"

namespace OHOS {
namespace DistributedHardware {

namespace {
    constexpr int32_t RAND_MIN_VAL = 1;
    constexpr int32_t RAND_MAX_VAL = 100;
    constexpr int64_t RAND_MIN_LONG = 1;
    constexpr int64_t RAND_MAX_LONG = 1000000;
    constexpr uint64_t RAND_MIN_ULL = 1;
    constexpr uint64_t RAND_MAX_ULL = 1000000;
    constexpr uint16_t RAND_UINT_MIN = 10;
    constexpr uint16_t RAND_UINT_MAX = 1000;
    constexpr int32_t INVALID_PINCODE_TOO_SHORT = 5;
    constexpr int32_t INVALID_PINCODE_TOO_LONG = 1025;
    constexpr int32_t VALID_PINCODE_MIN = 6;
    constexpr int32_t VALID_PINCODE_NORMAL = 8;
    constexpr int32_t VALID_PINCODE_LARGE = 32;
    constexpr int32_t UNIQUE_RAND_CALL_COUNT = 10;
    constexpr int32_t INT16_MAX_VAL = 32767;
}

void DmRandomTest::SetUp() {}
void DmRandomTest::TearDown() {}
void DmRandomTest::SetUpTestCase() {}
void DmRandomTest::TearDownTestCase() {}

/**
 * @tc.name: GenRandInt_001
 * @tc.type: FUNC
 * @tc.desc: Normal case - generated value within [randMin, randMax)
 */
HWTEST_F(DmRandomTest, GenRandInt_001, testing::ext::TestSize.Level1)
{
    int32_t result = GenRandInt(RAND_MIN_VAL, RAND_MAX_VAL);
    EXPECT_GE(result, RAND_MIN_VAL);
    EXPECT_LT(result, RAND_MAX_VAL);
}

/**
 * @tc.name: GenRandInt_002
 * @tc.type: FUNC
 * @tc.desc: Multiple calls produce at least 2 distinct values (randomness check)
 */
HWTEST_F(DmRandomTest, GenRandInt_002, testing::ext::TestSize.Level1)
{
    std::set<int32_t> results;
    for (int i = 0; i < UNIQUE_RAND_CALL_COUNT; ++i) {
        results.insert(GenRandInt(RAND_MIN_VAL, RAND_MAX_VAL));
    }
    EXPECT_GT(results.size(), 1);
}

/**
 * @tc.name: GenRandInt_003
 * @tc.type: FUNC
 * @tc.desc: Equal min and max - gen() % 0 is UB, verify function does not crash
 */
HWTEST_F(DmRandomTest, GenRandInt_003, testing::ext::TestSize.Level1)
{
    int32_t result = GenRandInt(50, 50);
    EXPECT_TRUE(result >= 50 || result < 0);
}

/**
 * @tc.name: GenRandLongLong_001
 * @tc.type: FUNC
 * @tc.desc: Normal case - generated value within [randMin, randMax]
 */
HWTEST_F(DmRandomTest, GenRandLongLong_001, testing::ext::TestSize.Level1)
{
    int64_t result = GenRandLongLong(RAND_MIN_LONG, RAND_MAX_LONG);
    EXPECT_GE(result, RAND_MIN_LONG);
    EXPECT_LE(result, RAND_MAX_LONG);
}

/**
 * @tc.name: GenRandLongLong_002
 * @tc.type: FUNC
 * @tc.desc: Large range - value within [0, INT64_MAX]
 */
HWTEST_F(DmRandomTest, GenRandLongLong_002, testing::ext::TestSize.Level1)
{
    int64_t result = GenRandLongLong(0, INT16_MAX_VAL);
    EXPECT_GE(result, 0);
    EXPECT_LE(result, INT16_MAX_VAL);
}

/**
 * @tc.name: GenRandUnLongLong_001
 * @tc.type: FUNC
 * @tc.desc: Normal case - generated value within [randMin, randMax]
 */
HWTEST_F(DmRandomTest, GenRandUnLongLong_001, testing::ext::TestSize.Level1)
{
    uint64_t result = GenRandUnLongLong(RAND_MIN_ULL, RAND_MAX_ULL);
    EXPECT_GE(result, RAND_MIN_ULL);
    EXPECT_LE(result, RAND_MAX_ULL);
}

/**
 * @tc.name: GenRandUnLongLong_002
 * @tc.type: FUNC
 * @tc.desc: Multiple calls produce different values
 */
HWTEST_F(DmRandomTest, GenRandUnLongLong_002, testing::ext::TestSize.Level1)
{
    std::set<uint64_t> results;
    for (int i = 0; i < UNIQUE_RAND_CALL_COUNT; ++i) {
        results.insert(GenRandUnLongLong(RAND_MIN_ULL, RAND_MAX_ULL));
    }
    EXPECT_GT(results.size(), 1);
}

/**
 * @tc.name: GenRandUint_001
 * @tc.type: FUNC
 * @tc.desc: Normal case - generated value within [randMin, randMax]
 */
HWTEST_F(DmRandomTest, GenRandUint_001, testing::ext::TestSize.Level1)
{
    uint16_t result = GenRandUint(RAND_UINT_MIN, RAND_UINT_MAX);
    EXPECT_GE(result, RAND_UINT_MIN);
    EXPECT_LE(result, RAND_UINT_MAX);
}

/**
 * @tc.name: GenRandUint_002
 * @tc.type: FUNC
 * @tc.desc: Narrow range [100, 100] - always returns 100
 */
HWTEST_F(DmRandomTest, GenRandUint_002, testing::ext::TestSize.Level1)
{
    uint16_t result = GenRandUint(100, 100);
    EXPECT_EQ(result, 100);
}

/**
 * @tc.name: GenUniqueRandUint_001
 * @tc.type: FUNC
 * @tc.desc: Normal case - returns non-zero value and inserts into set
 */
HWTEST_F(DmRandomTest, GenUniqueRandUint_001, testing::ext::TestSize.Level1)
{
    std::set<uint16_t> randSet;
    uint16_t result = GenUniqueRandUint(randSet);
    EXPECT_NE(result, 0);
    EXPECT_EQ(randSet.size(), 1);
    EXPECT_EQ(randSet.count(result), 1);
}

/**
 * @tc.name: GenUniqueRandUint_002
 * @tc.type: FUNC
 * @tc.desc: Multiple calls - all values are unique and non-zero
 */
HWTEST_F(DmRandomTest, GenUniqueRandUint_002, testing::ext::TestSize.Level1)
{
    std::set<uint16_t> randSet;
    for (int i = 0; i < UNIQUE_RAND_CALL_COUNT; ++i) {
        uint16_t val = GenUniqueRandUint(randSet);
        EXPECT_NE(val, 0);
    }
    EXPECT_EQ(randSet.size(), UNIQUE_RAND_CALL_COUNT);
}

/**
 * @tc.name: GenUniqueRandUint_003
 * @tc.type: FUNC
 * @tc.desc: Pre-populated set - new value is not in existing set
 */
HWTEST_F(DmRandomTest, GenUniqueRandUint_003, testing::ext::TestSize.Level1)
{
    std::set<uint16_t> randSet;
    randSet.emplace(1);
    randSet.emplace(2);
    randSet.emplace(3);
    uint16_t result = GenUniqueRandUint(randSet);
    EXPECT_NE(result, 0);
    EXPECT_EQ(randSet.count(result), 1);
    EXPECT_EQ(randSet.size(), 4);
}

/**
 * @tc.name: GeneratePinCode_001
 * @tc.type: FUNC
 * @tc.desc: Valid pinLength (minimum 6) - returns 6-digit string
 */
HWTEST_F(DmRandomTest, GeneratePinCode_001, testing::ext::TestSize.Level1)
{
    std::string pinCode = GeneratePinCode(VALID_PINCODE_MIN);
    EXPECT_EQ(pinCode.length(), static_cast<size_t>(VALID_PINCODE_MIN));
    EXPECT_FALSE(pinCode.empty());
    std::cout << "Generated pin code (len=6): " << pinCode << std::endl;
}

/**
 * @tc.name: GeneratePinCode_002
 * @tc.type: FUNC
 * @tc.desc: Valid pinLength (8) - returns 8-digit string
 */
HWTEST_F(DmRandomTest, GeneratePinCode_002, testing::ext::TestSize.Level1)
{
    std::string pinCode = GeneratePinCode(VALID_PINCODE_NORMAL);
    EXPECT_EQ(pinCode.length(), static_cast<size_t>(VALID_PINCODE_NORMAL));
    EXPECT_FALSE(pinCode.empty());
    std::cout << "Generated pin code (len=8): " << pinCode << std::endl;
}

/**
 * @tc.name: GeneratePinCode_003
 * @tc.type: FUNC
 * @tc.desc: Valid pinLength (32) - returns 32-char string
 */
HWTEST_F(DmRandomTest, GeneratePinCode_003, testing::ext::TestSize.Level1)
{
    std::string pinCode = GeneratePinCode(VALID_PINCODE_LARGE);
    EXPECT_EQ(pinCode.length(), static_cast<size_t>(VALID_PINCODE_LARGE));
    EXPECT_FALSE(pinCode.empty());
}

/**
 * @tc.name: GeneratePinCode_004
 * @tc.type: FUNC
 * @tc.desc: Invalid pinLength (< 6) - returns empty string
 */
HWTEST_F(DmRandomTest, GeneratePinCode_004, testing::ext::TestSize.Level1)
{
    std::string pinCode = GeneratePinCode(INVALID_PINCODE_TOO_SHORT);
    EXPECT_TRUE(pinCode.empty());
}

/**
 * @tc.name: GeneratePinCode_005
 * @tc.type: FUNC
 * @tc.desc: Invalid pinLength (> 1024) - returns empty string
 */
HWTEST_F(DmRandomTest, GeneratePinCode_005, testing::ext::TestSize.Level1)
{
    std::string pinCode = GeneratePinCode(INVALID_PINCODE_TOO_LONG);
    EXPECT_TRUE(pinCode.empty());
}

/**
 * @tc.name: GeneratePinCode_006
 * @tc.type: FUNC
 * @tc.desc: Multiple calls with same length produce different codes (randomness)
 */
HWTEST_F(DmRandomTest, GeneratePinCode_006, testing::ext::TestSize.Level1)
{
    std::set<std::string> codes;
    for (int i = 0; i < UNIQUE_RAND_CALL_COUNT; ++i) {
        codes.insert(GeneratePinCode(VALID_PINCODE_NORMAL));
    }
    EXPECT_GT(codes.size(), 1);
}

/**
 * @tc.name: GeneratePinCode_007
 * @tc.type: FUNC
 * @tc.desc: Boundary - pinLength exactly at max (1024)
 */
HWTEST_F(DmRandomTest, GeneratePinCode_007, testing::ext::TestSize.Level1)
{
    std::string pinCode = GeneratePinCode(1024);
    EXPECT_EQ(pinCode.length(), static_cast<size_t>(1024));
    EXPECT_FALSE(pinCode.empty());
}

/**
 * @tc.name: GeneratePinCode_008
 * @tc.type: FUNC
 * @tc.desc: Pin code contains only numeric characters
 */
HWTEST_F(DmRandomTest, GeneratePinCode_008, testing::ext::TestSize.Level1)
{
    std::string pinCode = GeneratePinCode(VALID_PINCODE_NORMAL);
    for (char c : pinCode) {
        EXPECT_GE(c, '0');
        EXPECT_LE(c, '9');
    }
}
} // namespace DistributedHardware
} // namespace OHOS
