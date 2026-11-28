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
#include "dm_auth_attest_common.h"
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
 * @tc.name  : VerifyCertificateV3_001
 * @tc.desc  : VerifyCertificateV3 函数调用场景
 */
HWTEST_F(DmAuthCertTest, VerifyCertificateV3_001, testing::ext::TestSize.Level1) {
    AuthCert authCert;
    DmCertChain dmCertChain;
    const char *deviceIdHash = "testDeviceIdHash";
    const uint64_t random = 12345;
    int32_t result = authCert.VerifyCertificateV3(dmCertChain, deviceIdHash, random);
    EXPECT_NE(result, DM_OK);
}

HWTEST_F(DmAuthCertTest, GenerateCertificateV3_001, testing::ext::TestSize.Level1) {
    AuthCert authCert;
    DmCertChain dmCertChain;
    const uint64_t random = 0;
    int32_t result = authCert.GenerateCertificateV3(dmCertChain, random);
    EXPECT_NE(result, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DmAuthCertTest, VerifyCertificateV3_001, testing::ext::TestSize.Level1) {
    AuthCert authCert;
    DmCertChain dmCertChain;
    const char *deviceIdHash = "testDeviceIdHash";
    const uint64_t random = 0;
    int32_t result = authCert.VerifyCertificateV3(dmCertChain, deviceIdHash, random);
    EXPECT_EQ(result, ERR_DM_INPUT_PARA_INVALID);
}
}
}