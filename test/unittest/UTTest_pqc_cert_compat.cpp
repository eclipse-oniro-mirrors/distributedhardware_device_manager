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

#include "UTTest_pqc_cert_compat.h"

#include "dm_anonymous.h"
#include "dm_auth_cert_ext_mock.h"
#include "dm_error_type.h"

namespace OHOS {
namespace DistributedHardware {

void PqcCertCompatTest::SetUpTestCase()
{
}

void PqcCertCompatTest::TearDownTestCase()
{
}

void PqcCertCompatTest::SetUp()
{
}

void PqcCertCompatTest::TearDown()
{
}

namespace {
constexpr uint64_t TEST_CERT_RANDOM = 12345;

// Drives the source-side cert generation for the given sink (peer) version. The
// algorithm actually taken is observed through the mock injected by AuthCertExtMockGuard.
void GenerateSourceCert(const std::string &peerSinkVersion)
{
    auto context = std::make_shared<DmAuthContext>();
    context->accessee.dmVersion = peerSinkVersion;
    context->accessee.certRandom = TEST_CERT_RANDOM;
    AuthSrcConfirmState::GenerateCertificate(context);
}

// Drives the sink-side cert verification for the given source (peer) version and returns
// the VerifyCertificate result. accesser.cert holds a well-formed serialized chain.
int32_t VerifySinkCert(const std::string &peerSourceVersion)
{
    auto context = std::make_shared<DmAuthContext>();
    context->accesser.dmVersion = peerSourceVersion;
    context->accesser.deviceIdHash = "testDeviceIdHash";
    context->accessee.certRandom = TEST_CERT_RANDOM;
    context->accesser.cert = BuildMockCertChainJson();
    auto authState = std::make_shared<AuthSinkDataSyncState>();
    return authState->VerifyCertificate(context);
}
} // namespace

/**
 * @tc.name: PQC_NewNew_VersionAbove5_1_8_SelectV3
 * @tc.desc: both devices >= 5.1.8 negotiate the PQC V3 algorithm on generate and verify
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(PqcCertCompatTest, PQC_NewNew_VersionAbove5_1_8_SelectV3, testing::ext::TestSize.Level1)
{
    auto mockExt = std::make_shared<DmAuthCertExtMock>();
    AuthCertExtMockGuard guard(mockExt);
#ifdef DEVICE_MANAGER_COMMON_FLAG
    GenerateSourceCert(DM_VERSION_5_1_8);
    int32_t verifyRet = VerifySinkCert(DM_VERSION_5_1_8);
    EXPECT_EQ(mockExt->generateV3Count, 0u);
    EXPECT_EQ(mockExt->verifyV3Count, 0u);
    EXPECT_EQ(verifyRet, DM_OK);
#else
    GenerateSourceCert(DM_VERSION_5_1_8);
    int32_t verifyRet = VerifySinkCert(DM_VERSION_5_1_8);
    // BR-2: source and sink must use the same PQC algorithm on both ends
    EXPECT_EQ(mockExt->generateV3Count, 1u);
    EXPECT_EQ(mockExt->verifyV3Count, 1u);
    EXPECT_EQ(mockExt->generateV2Count, 0u);
    EXPECT_EQ(mockExt->verifyV2Count, 0u);
    EXPECT_EQ(verifyRet, DM_OK);
#endif
}

/**
 * @tc.name: PQC_ErrorCode_VerifyCertFailed_Unchanged
 * @tc.desc: PQC V3 verify failure maps to the existing ERR_DM_VERIFY_CERT_FAILED value
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(PqcCertCompatTest, PQC_ErrorCode_VerifyCertFailed_Unchanged, testing::ext::TestSize.Level1)
{
    EXPECT_EQ(ERR_DM_VERIFY_CERT_FAILED, 969298351);
    auto mockExt = std::make_shared<DmAuthCertExtMock>();
    AuthCertExtMockGuard guard(mockExt);
#ifndef DEVICE_MANAGER_COMMON_FLAG
    mockExt->verifyV3Ret = ERR_DM_VERIFY_CERT_FAILED;
#endif
    int32_t verifyRet = VerifySinkCert(DM_VERSION_5_1_8);
#ifdef DEVICE_MANAGER_COMMON_FLAG
    EXPECT_EQ(verifyRet, DM_OK);
#else
    EXPECT_EQ(verifyRet, ERR_DM_VERIFY_CERT_FAILED);
#endif
}

/**
 * @tc.name: PQC_ErrorCode_DeserialCertFailed_Unchanged
 * @tc.desc: malformed cert chain json maps to the existing ERR_DM_DESERIAL_CERT_FAILED value
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(PqcCertCompatTest, PQC_ErrorCode_DeserialCertFailed_Unchanged, testing::ext::TestSize.Level1)
{
    EXPECT_EQ(ERR_DM_DESERIAL_CERT_FAILED, 969298350);
    auto mockExt = std::make_shared<DmAuthCertExtMock>();
    AuthCertExtMockGuard guard(mockExt);
    auto context = std::make_shared<DmAuthContext>();
    context->accesser.dmVersion = DM_VERSION_5_1_8;
    context->accesser.deviceIdHash = "testDeviceIdHash";
    context->accessee.certRandom = TEST_CERT_RANDOM;
    context->accesser.cert = "not_a_cert_chain_json";
    auto authState = std::make_shared<AuthSinkDataSyncState>();
    int32_t verifyRet = authState->VerifyCertificate(context);
#ifdef DEVICE_MANAGER_COMMON_FLAG
    EXPECT_EQ(verifyRet, DM_OK);
#else
    EXPECT_EQ(verifyRet, ERR_DM_DESERIAL_CERT_FAILED);
    EXPECT_EQ(mockExt->verifyV3Count, 0u);
#endif
}

/**
 * @tc.name: PQC_NewOld_V2_Compat_5_1_5
 * @tc.desc: new source downgrades to V2 for a 5.1.3 ~ 5.1.7 sink (AC-2.1)
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(PqcCertCompatTest, PQC_NewOld_V2_Compat_5_1_5, testing::ext::TestSize.Level1)
{
    auto mockExt = std::make_shared<DmAuthCertExtMock>();
    AuthCertExtMockGuard guard(mockExt);
#ifdef DEVICE_MANAGER_COMMON_FLAG
    GenerateSourceCert(DM_VERSION_5_1_5);
    EXPECT_EQ(mockExt->generateV2Count, 0u);
#else
    // new device (>= 5.1.8 code) sees old sink 5.1.5 and picks the traditional V2 path;
    // the old sink's pinned code also picks V2 for a 5.1.8 source, so both ends match
    GenerateSourceCert(DM_VERSION_5_1_5);
    EXPECT_EQ(mockExt->generateV2Count, 1u);
    EXPECT_EQ(mockExt->generateV3Count, 0u);
    EXPECT_EQ(mockExt->generateV1Count, 0u);
#endif
}

/**
 * @tc.name: PQC_NewOld_V1_Compat_5_1_1
 * @tc.desc: new source downgrades to V1 for a 5.1.0 ~ 5.1.3 sink (AC-2.2)
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(PqcCertCompatTest, PQC_NewOld_V1_Compat_5_1_1, testing::ext::TestSize.Level1)
{
    auto mockExt = std::make_shared<DmAuthCertExtMock>();
    AuthCertExtMockGuard guard(mockExt);
#ifdef DEVICE_MANAGER_COMMON_FLAG
    GenerateSourceCert("5.1.1");
    EXPECT_EQ(mockExt->generateV1Count, 0u);
#else
    GenerateSourceCert("5.1.1");
    EXPECT_EQ(mockExt->generateV1Count, 1u);
    EXPECT_EQ(mockExt->generateV3Count, 0u);
    EXPECT_EQ(mockExt->generateV2Count, 0u);
#endif
}

/**
 * @tc.name: PQC_NewOld_Skip_Compat_5_0_5
 * @tc.desc: sink skips cert verification for a pre-5.1.0 source (AC-2.3)
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(PqcCertCompatTest, PQC_NewOld_Skip_Compat_5_0_5, testing::ext::TestSize.Level1)
{
    auto mockExt = std::make_shared<DmAuthCertExtMock>();
    AuthCertExtMockGuard guard(mockExt);
    int32_t verifyRet = VerifySinkCert(DM_VERSION_5_0_5);
    EXPECT_EQ(verifyRet, DM_OK);
    EXPECT_EQ(mockExt->verifyV1Count, 0u);
    EXPECT_EQ(mockExt->verifyV2Count, 0u);
    EXPECT_EQ(mockExt->verifyV3Count, 0u);
}

/**
 * @tc.name: PQC_OldNew_Reverse_Compat
 * @tc.desc: new sink keeps the traditional V2 path for an old (< 5.1.8) source (AC-2.4)
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(PqcCertCompatTest, PQC_OldNew_Reverse_Compat, testing::ext::TestSize.Level1)
{
    auto mockExt = std::make_shared<DmAuthCertExtMock>();
    AuthCertExtMockGuard guard(mockExt);
#ifdef DEVICE_MANAGER_COMMON_FLAG
    int32_t verifyRet = VerifySinkCert(DM_VERSION_5_1_5);
    EXPECT_EQ(mockExt->verifyV2Count, 0u);
    EXPECT_EQ(verifyRet, DM_OK);
#else
    // old source (< 5.1.8 code) generates V2 for a 5.1.8 sink; the new sink must verify
    // with the same traditional V2 algorithm instead of the PQC V3 path
    int32_t verifyRet = VerifySinkCert(DM_VERSION_5_1_5);
    EXPECT_EQ(mockExt->verifyV2Count, 1u);
    EXPECT_EQ(mockExt->verifyV3Count, 0u);
    EXPECT_EQ(mockExt->verifyV1Count, 0u);
    EXPECT_EQ(verifyRet, DM_OK);
#endif
}

/**
 * @tc.name: PQC_VersionIncompatible_Below5_0_99
 * @tc.desc: peer below the old-version estimate stays version-incompatible (AC-3.3)
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(PqcCertCompatTest, PQC_VersionIncompatible_Below5_0_99, testing::ext::TestSize.Level1)
{
    // existing minimum-version rejection logic is untouched by the PQC change
    EXPECT_FALSE(CompareVersion("5.0.50", DM_VERSION_5_0_OLD_MAX));
    EXPECT_TRUE(CompareVersion("5.0.99", "5.0.98"));
}
} // namespace DistributedHardware
} // namespace OHOS
