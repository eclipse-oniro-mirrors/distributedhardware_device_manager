/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include "dm_auth_cert.h"
#include "dm_error_type.h"
#include "dm_log.h"
#include "dm_auth_cert_ext_mock.h"
#include "UTTest_dm_auth_cert.h"

namespace OHOS {
namespace DistributedHardware {

void DmAuthCertTest::SetUp()
{
}
void DmAuthCertTest::TearDown()
{
}
void DmAuthCertTest::SetUpTestCase()
{
}
void DmAuthCertTest::TearDownTestCase()
{
}

/**
 * @tc.name  : VerifyCertificate_ShouldReturnFailed_WhenCertModuleNotLoaded
 * @tc.number: VerifyCertificateTest_001
 * @tc.desc  : 测试当认证证书模块未加载时,VerifyCertificate 函数应返回 ERR_DM_FAILED
 */
HWTEST_F(DmAuthCertTest, VerifyCertificate_001, testing::ext::TestSize.Level1) {
    DmCertChain dmCertChain;
    AuthCert authCert;
    const char *deviceIdHash = "testDeviceIdHash";
    int32_t result = authCert.VerifyCertificate(dmCertChain, deviceIdHash);
    EXPECT_NE(result, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: IsDMAdapterAuthCertLoaded_001
 * @tc.type: FUNC
 */
HWTEST_F(DmAuthCertTest, IsDMAdapterAuthCertLoaded_001, testing::ext::TestSize.Level1) {
    AuthCert authCert;
    authCert.isAdapterAuthCertSoLoaded_ = false;
    bool result = authCert.IsDMAdapterAuthCertLoaded();
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: IsDMAdapterAuthCertLoaded_002
 * @tc.type: FUNC
 */
HWTEST_F(DmAuthCertTest, IsDMAdapterAuthCertLoaded_002, testing::ext::TestSize.Level1) {
    AuthCert authCert;
    authCert.isAdapterAuthCertSoLoaded_ = true;
    authCert.dmAuthCertExt_ = std::shared_ptr<IDMAuthCertExt>();
    bool result = authCert.IsDMAdapterAuthCertLoaded();
    EXPECT_NE(result, true);
}

/**
 * @tc.name: GenerateCertificate_001
 * @tc.type: FUNC
 */
HWTEST_F(DmAuthCertTest, GenerateCertificate_001, testing::ext::TestSize.Level1) {
    AuthCert authCert;
    DmCertChain dmCertChain;
    int32_t result = authCert.GenerateCertificate(dmCertChain);
    int32_t errCode = -10005;
    EXPECT_NE(result, errCode);
}

/**
 * @tc.name  : GenerateCertificateV3_001
 * @tc.desc  : 测试当认证证书模块未加载时,GenerateCertificateV3 函数应返回 ERR_DM_FAILED
 */
HWTEST_F(DmAuthCertTest, GenerateCertificateV3_001, testing::ext::TestSize.Level1) {
    AuthCert authCert;
    DmCertChain dmCertChain;
    const uint64_t random = 12345;
    int32_t result = authCert.GenerateCertificateV3(dmCertChain, random);
    EXPECT_EQ(result, ERR_DM_FAILED);
}

/**
 * @tc.name  : GenerateCertificateV3_DelegatesToExt_001
 * @tc.desc  : 测试 GenerateCertificateV3 委托至 IDMAuthCertExt 实现并被调用一次
 */
HWTEST_F(DmAuthCertTest, GenerateCertificateV3_DelegatesToExt_001, testing::ext::TestSize.Level1) {
    AuthCert authCert;
    authCert.isAdapterAuthCertSoLoaded_ = true;
    authCert.dmAuthCertExt_ = std::make_shared<DmAuthCertExtMock>();
    DmCertChain dmCertChain;
    const uint64_t random = 12345;
    int32_t result = authCert.GenerateCertificateV3(dmCertChain, random);
    EXPECT_EQ(result, DM_OK);
    auto mock = std::static_pointer_cast<DmAuthCertExtMock>(authCert.dmAuthCertExt_);
    EXPECT_EQ(mock->generateV3Count, 1u);
    EXPECT_EQ(mock->generateV2Count, 0u);
    EXPECT_EQ(mock->generateV1Count, 0u);
    AuthAttestCommon::GetInstance().FreeDmCertChain(dmCertChain);
}

/**
 * @tc.name  : VerifyCertificateV3_001
 * @tc.desc  : 测试当认证证书模块未加载时,VerifyCertificateV3 函数应返回 ERR_DM_FAILED
 */
HWTEST_F(DmAuthCertTest, VerifyCertificateV3_001, testing::ext::TestSize.Level1) {
    AuthCert authCert;
    DmCertChain dmCertChain;
    const char *deviceIdHash = "testDeviceIdHash";
    const uint64_t random = 12345;
    int32_t result = authCert.VerifyCertificateV3(dmCertChain, deviceIdHash, random);
    EXPECT_EQ(result, ERR_DM_FAILED);
}

/**
 * @tc.name  : VerifyCertificateV3_DelegatesToExt_001
 * @tc.desc  : 测试 VerifyCertificateV3 委托至 IDMAuthCertExt 实现,成功与失败结果均透传
 */
HWTEST_F(DmAuthCertTest, VerifyCertificateV3_DelegatesToExt_001, testing::ext::TestSize.Level1) {
    AuthCert authCert;
    authCert.isAdapterAuthCertSoLoaded_ = true;
    authCert.dmAuthCertExt_ = std::make_shared<DmAuthCertExtMock>();
    DmCertChain dmCertChain;
    const char *deviceIdHash = "testDeviceIdHash";
    const uint64_t random = 12345;
    int32_t result = authCert.VerifyCertificateV3(dmCertChain, deviceIdHash, random);
    EXPECT_EQ(result, DM_OK);
    auto mock = std::static_pointer_cast<DmAuthCertExtMock>(authCert.dmAuthCertExt_);
    EXPECT_EQ(mock->verifyV3Count, 1u);
    EXPECT_EQ(mock->verifyV2Count, 0u);
    EXPECT_EQ(mock->verifyV1Count, 0u);

    mock->Reset();
    mock->verifyV3Ret = ERR_DM_VERIFY_CERT_FAILED;
    result = authCert.VerifyCertificateV3(dmCertChain, deviceIdHash, random);
    EXPECT_EQ(result, ERR_DM_VERIFY_CERT_FAILED);
}
}
}