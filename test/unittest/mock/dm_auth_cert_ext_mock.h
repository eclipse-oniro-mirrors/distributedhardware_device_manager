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

#ifndef OHOS_DM_AUTH_CERT_EXT_MOCK_H
#define OHOS_DM_AUTH_CERT_EXT_MOCK_H

#include <new>

#include "dm_auth_attest_common.h"
#include "dm_auth_cert.h"
#include "dm_error_type.h"
#include "i_dm_auth_cert_ext.h"

namespace OHOS {
namespace DistributedHardware {
// Test-only IDMAuthCertExt implementation. It records which certificate algorithm
// (V1/V2/V3) was selected by version-negotiation branches and returns configurable
// results, so branch tests observe the chosen path without the real
// libdm_auth_cert.z.so. It is only meaningful in unit-test builds where the
// DEVICE_MANAGER_COMMON_FLAG open-source cert bypass is not compiled out.
class DmAuthCertExtMock : public IDMAuthCertExt {
public:
    DmAuthCertExtMock() = default;
    ~DmAuthCertExtMock() override = default;

    int32_t GenerateCertificate(DmCertChain &dmCertChain) override
    {
        generateV1Count++;
        FillCertChain(dmCertChain);
        return generateRet;
    }

    int32_t VerifyCertificate(const DmCertChain &dmCertChain, const char *deviceIdHash) override
    {
        (void)dmCertChain;
        (void)deviceIdHash;
        verifyV1Count++;
        return verifyV1Ret;
    }

    int32_t GenerateCertificateV2(DmCertChain &dmCertChain, const uint64_t random) override
    {
        (void)random;
        generateV2Count++;
        FillCertChain(dmCertChain);
        return generateRet;
    }

    int32_t VerifyCertificateV2(const DmCertChain &dmCertChain, const char *deviceIdHash,
        const uint64_t random) override
    {
        (void)dmCertChain;
        (void)deviceIdHash;
        (void)random;
        verifyV2Count++;
        return verifyV2Ret;
    }

    int32_t GenerateCertificateV3(DmCertChain &dmCertChain, const uint64_t random) override
    {
        (void)random;
        generateV3Count++;
        FillCertChain(dmCertChain);
        return generateRet;
    }

    int32_t VerifyCertificateV3(const DmCertChain &dmCertChain, const char *deviceIdHash,
        const uint64_t random) override
    {
        (void)dmCertChain;
        (void)deviceIdHash;
        (void)random;
        verifyV3Count++;
        return verifyV3Ret;
    }

    void Reset()
    {
        generateV1Count = 0;
        generateV2Count = 0;
        generateV3Count = 0;
        verifyV1Count = 0;
        verifyV2Count = 0;
        verifyV3Count = 0;
        generateRet = DM_OK;
        verifyV1Ret = DM_OK;
        verifyV2Ret = DM_OK;
        verifyV3Ret = DM_OK;
    }

    uint32_t generateV1Count = 0;
    uint32_t generateV2Count = 0;
    uint32_t generateV3Count = 0;
    uint32_t verifyV1Count = 0;
    uint32_t verifyV2Count = 0;
    uint32_t verifyV3Count = 0;
    int32_t generateRet = DM_OK;
    int32_t verifyV1Ret = DM_OK;
    int32_t verifyV2Ret = DM_OK;
    int32_t verifyV3Ret = DM_OK;

private:
    // GenerateCertificate* callers hand over an uninitialized stack chain; overwrite it
    // with a valid 4-cert chain so SerializeDmCertChain/FreeDmCertChain stay safe.
    static void FillCertChain(DmCertChain &dmCertChain)
    {
        dmCertChain.cert = new (std::nothrow) DmBlob[DM_CERTS_COUNT];
        dmCertChain.certCount = DM_CERTS_COUNT;
        for (uint32_t i = 0; i < DM_CERTS_COUNT; ++i) {
            dmCertChain.cert[i].size = 1;
            dmCertChain.cert[i].data = new (std::nothrow) uint8_t[1]();
        }
    }
};

// Injects mock into the AuthCert singleton for the guard's lifetime and restores the
// previous state on destruction, keeping cert branch tests isolated from each other.
class AuthCertExtMockGuard {
public:
    explicit AuthCertExtMockGuard(const std::shared_ptr<DmAuthCertExtMock> &mock) : mock_(mock)
    {
        savedLoaded_ = AuthCert::GetInstance().isAdapterAuthCertSoLoaded_;
        savedExt_ = AuthCert::GetInstance().dmAuthCertExt_;
        AuthCert::GetInstance().isAdapterAuthCertSoLoaded_ = true;
        AuthCert::GetInstance().dmAuthCertExt_ = mock_;
    }

    ~AuthCertExtMockGuard()
    {
        AuthCert::GetInstance().isAdapterAuthCertSoLoaded_ = savedLoaded_;
        AuthCert::GetInstance().dmAuthCertExt_ = savedExt_;
    }

private:
    std::shared_ptr<DmAuthCertExtMock> mock_;
    bool savedLoaded_ = false;
    std::shared_ptr<IDMAuthCertExt> savedExt_;
};

// Builds a serialized 4-cert chain accepted by DeserializeDmCertChain, so sink-side
// branch tests can get past cert deserialization and reach the verify branch.
inline std::string BuildMockCertChainJson()
{
    DmCertChain chain;
    chain.cert = new (std::nothrow) DmBlob[DM_CERTS_COUNT];
    chain.certCount = DM_CERTS_COUNT;
    for (uint32_t i = 0; i < DM_CERTS_COUNT; ++i) {
        chain.cert[i].size = 1;
        chain.cert[i].data = new (std::nothrow) uint8_t[1]();
    }
    std::string certChainJson = AuthAttestCommon::GetInstance().SerializeDmCertChain(&chain);
    AuthAttestCommon::GetInstance().FreeDmCertChain(chain);
    return certChainJson;
}
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_AUTH_CERT_EXT_MOCK_H
