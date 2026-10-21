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
#include "app_manager_3rd_Refactor.h"

#include <cstring>
#include <securec.h>

#include "accesstoken_kit.h"
#include "access_token.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "parameter.h"
#include "system_ability_definition.h"
#include "tokenid_kit.h"

#include "dm_anonymous_3rd.h"
#include "dm_error_type_3rd.h"
#include "dm_log_3rd.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace DistributedHardware {

DM_IMPLEMENT_SINGLE_INSTANCE_3RD(AppManager3rdRefactor);

int32_t AppManager3rdRefactor::GetAppIdByPkgName(const std::string &pkgName,
    std::string &appId, const int32_t userId)
{
    if (pkgName.empty()) {
        LOGE("Invalid parameter, pkgName is empty.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    LOGD("PkgName %{public}s, userId %{public}d", GetAnonyString(pkgName).c_str(), userId);
    std::string appIdKey = pkgName + "#" + std::to_string(userId);
    std::lock_guard<std::mutex> lock(appIdMapLock_);
    if (appIdMap_.find(appIdKey) == appIdMap_.end()) {
        LOGE("appIdKey get appid failed.");
        return ERR_DM_FAILED;
    }
    CHECK_SIZE_RETURN(appIdMap_, ERR_DM_FAILED);
    appId = appIdMap_[appIdKey];
    LOGI("appId %{public}s.", GetAnonyString(appId).c_str());
    return DM_OK;
}

bool AppManager3rdRefactor::GetBundleManagerProxy(sptr<AppExecFwk::IBundleMgr> &bundleManager)
{
    sptr<ISystemAbilityManager> sam =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        LOGE("Failed to get system ability mgr.");
        return false;
    }
    sptr<IRemoteObject> remoteObject = sam->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        LOGE("Failed to get bundle manager service.");
        return false;
    }
    bundleManager = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (bundleManager == nullptr) {
        LOGE("bundleManager is nullptr.");
        return false;
    }
    return true;
}

bool AppManager3rdRefactor::IsSystemSA()
{
    AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    if (tokenCaller == 0) {
        LOGE("IsSystemSA GetCallingTokenID error.");
        return false;
    }
    ATokenTypeEnum tokenTypeFlag = AccessTokenKit::GetTokenTypeFlag(tokenCaller);
    if (tokenTypeFlag == ATokenTypeEnum::TOKEN_NATIVE) {
        return true;
    }
    return false;
}

bool AppManager3rdRefactor::IsSystemApp()
{
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    return OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
}

int32_t AppManager3rdRefactor::GetCallerName(bool &isSystemSA, std::string &callerName)
{
    AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    if (tokenCaller == 0) {
        LOGE("GetCallingTokenID error.");
        return ERR_DM_FAILED;
    }
    ATokenTypeEnum tokenTypeFlag = AccessTokenKit::GetTokenTypeFlag(tokenCaller);
    if (tokenTypeFlag == ATokenTypeEnum::TOKEN_HAP) {
        isSystemSA = false;
        HapTokenInfo tokenInfo;
        if (AccessTokenKit::GetHapTokenInfo(tokenCaller, tokenInfo) != EOK) {
            LOGE("GetHapTokenInfo failed.");
            return ERR_DM_FAILED;
        }
        callerName = std::move(tokenInfo.bundleName);
    } else if (tokenTypeFlag == ATokenTypeEnum::TOKEN_NATIVE) {
        isSystemSA = true;
        NativeTokenInfo tokenInfo;
        if (AccessTokenKit::GetNativeTokenInfo(tokenCaller, tokenInfo) != EOK) {
            LOGE("GetNativeTokenInfo failed.");
            return ERR_DM_FAILED;
        }
        callerName = std::move(tokenInfo.processName);
    } else {
        LOGE("Failed, unsupported process.");
        return ERR_DM_FAILED;
    }
    return DM_OK;
}

int32_t AppManager3rdRefactor::GetBundleNameByTokenId(int64_t tokenId, std::string &bundleName)
{
    if (tokenId < 0) {
        LOGE("GetBundleNameByTokenId error.");
        return ERR_DM_FAILED;
    }
    AccessTokenID tokenIdTemp = static_cast<AccessTokenID>(tokenId);
    ATokenTypeEnum tokenTypeFlag = AccessTokenKit::GetTokenTypeFlag(tokenIdTemp);
    if (tokenTypeFlag == ATokenTypeEnum::TOKEN_HAP) {
        HapTokenInfo tokenInfo;
        if (AccessTokenKit::GetHapTokenInfo(tokenIdTemp, tokenInfo) != EOK) {
            LOGE("GetHapTokenInfo failed.");
            return ERR_DM_FAILED;
        }
        bundleName = std::move(tokenInfo.bundleName);
    } else if (tokenTypeFlag == ATokenTypeEnum::TOKEN_NATIVE) {
        NativeTokenInfo tokenInfo;
        if (AccessTokenKit::GetNativeTokenInfo(tokenIdTemp, tokenInfo) != EOK) {
            LOGE("GetNativeTokenInfo failed.");
            return ERR_DM_FAILED;
        }
        bundleName = std::move(tokenInfo.processName);
    } else {
        LOGE("Failed, unsupported process.");
        return ERR_DM_FAILED;
    }
    return DM_OK;
}

int32_t AppManager3rdRefactor::GetNativeTokenIdByName(const std::string &processName, uint32_t &tokenId)
{
    AccessTokenID nativeTokenId = AccessTokenKit::GetNativeTokenId(processName);
    if (nativeTokenId == INVALID_TOKENID) {
        LOGE("GetNativeTokenId failed.");
        return ERR_DM_FAILED;
    }
    ATokenTypeEnum tokenTypeFlag = AccessTokenKit::GetTokenTypeFlag(nativeTokenId);
    if (tokenTypeFlag != ATokenTypeEnum::TOKEN_NATIVE) {
        LOGE("nativeTokenId is not SA.");
        return ERR_DM_FAILED;
    }
    tokenId = static_cast<uint32_t>(nativeTokenId);
    return DM_OK;
}

int32_t AppManager3rdRefactor::GetHapTokenIdByName(int32_t userId, const std::string &bundleName,
    int32_t instIndex, uint32_t &tokenId)
{
    auto hapTokenId = AccessTokenKit::GetHapTokenID(userId, bundleName, instIndex);
    if (hapTokenId == 0) {
        LOGE("GetHapTokenId failed.");
        return ERR_DM_FAILED;
    }
    tokenId = static_cast<uint32_t>(hapTokenId);
    return DM_OK;
}

int32_t AppManager3rdRefactor::GetCallerProcessName(std::string &processName)
{
    AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    if (tokenCaller == 0) {
        LOGE("GetCallerProcessName GetCallingTokenID error.");
        return ERR_DM_FAILED;
    }
    ATokenTypeEnum tokenTypeFlag = AccessTokenKit::GetTokenTypeFlag(tokenCaller);
    if (tokenTypeFlag == ATokenTypeEnum::TOKEN_HAP) {
        HapTokenInfo tokenInfo;
        if (AccessTokenKit::GetHapTokenInfo(tokenCaller, tokenInfo) != EOK) {
            LOGE("GetHapTokenInfo failed.");
            return ERR_DM_FAILED;
        }
        processName = std::move(tokenInfo.bundleName);
        uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
        bool isSystemApp = OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
        if (!isSystemApp) {
            LOGE("GetCallerProcessName not system hap.");
            return ERR_DM_FAILED;
        }
    } else if (tokenTypeFlag == ATokenTypeEnum::TOKEN_NATIVE) {
        NativeTokenInfo tokenInfo;
        if (AccessTokenKit::GetNativeTokenInfo(tokenCaller, tokenInfo) != EOK) {
            LOGE("GetNativeTokenInfo failed.");
            return ERR_DM_FAILED;
        }
        processName = std::move(tokenInfo.processName);
    } else {
        LOGE("GetCallerProcessName failed, unsupported process.");
        return ERR_DM_FAILED;
    }
    return DM_OK;
}

int32_t AppManager3rdRefactor::GetBundleNameForSelf(std::string &bundleName)
{
    sptr<AppExecFwk::IBundleMgr> bundleManager = nullptr;
    if (!GetBundleManagerProxy(bundleManager)) {
        LOGE("Get bundleManager failed.");
        return ERR_DM_GET_BMS_FAILED;
    }
    if (bundleManager == nullptr) {
        LOGE("bundleManager is nullptr.");
        return ERR_DM_GET_BMS_FAILED;
    }
    AppExecFwk::BundleInfo bundleInfo;
    int32_t flags = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    int32_t ret = static_cast<int32_t>(bundleManager->GetBundleInfoForSelf(flags, bundleInfo));
    if (ret != ERR_OK) {
        LOGE("GetBundleInfoForSelf failed, ret=%{public}d.", ret);
        return ERR_DM_GET_BUNDLE_NAME_FAILED;
    }
    bundleName = bundleInfo.name;
    return DM_OK;
}

} // namespace DistributedHardware
} // namespace OHOS
