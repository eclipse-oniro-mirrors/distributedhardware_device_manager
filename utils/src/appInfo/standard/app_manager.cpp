/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "app_manager.h"

#include "accesstoken_kit.h"
#include "access_token.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"
#include "tokenid_kit.h"

#include "dm_anonymous.h"
#include "dm_constants.h"
#include "dm_log.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace DistributedHardware {
DM_IMPLEMENT_SINGLE_INSTANCE(AppManager);

const std::string AppManager::GetAppId()
{
    std::string appId = "";
    AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    if (AccessTokenKit::GetTokenTypeFlag(tokenId) != TOKEN_HAP) {
        LOGD("The caller is not token_hap.");
        return appId;
    }
    sptr<AppExecFwk::IBundleMgr> bundleManager = nullptr;
    if (!GetBundleManagerProxy(bundleManager)) {
        LOGE("get bundleManager failed.");
        return appId;
    }
    if (bundleManager == nullptr) {
        LOGE("bundleManager is nullptr.");
        return appId;
    }
    int32_t userId = -1;
    if (AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId) != ERR_OK) {
        LOGE("GetAppIdByCallingUid QueryActiveOsAccountIds failed.");
        return appId;
    }
    std::string BundleName = "";
    bundleManager->GetNameForUid(IPCSkeleton::GetCallingUid(), BundleName);
    AppExecFwk::BundleInfo bundleInfo;
    int32_t ret = bundleManager->GetBundleInfoV9(
        BundleName, static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO),
        bundleInfo, userId);
    if (ret != 0) {
        LOGE(" GetBundleInfoV9 failed %{public}d.", ret);
        return appId;
    }
    appId = bundleInfo.appId;
    return appId;
}

void AppManager::RegisterCallerAppId(const std::string &pkgName)
{
    if (pkgName.empty()) {
        LOGE("Invalid parameter, pkgName is empty.");
        return;
    }
    std::string appId = GetAppId();
    if (appId.empty()) {
        LOGE("PkgName %{public}s get appid failed.", pkgName.c_str());
        return;
    }
    LOGI("PkgName %{public}s, appId %{public}s.", pkgName.c_str(), GetAnonyString(appId).c_str());
    std::lock_guard<std::mutex> lock(appIdMapLock_);
    appIdMap_[pkgName] = appId;
}

void AppManager::UnRegisterCallerAppId(const std::string &pkgName)
{
    if (pkgName.empty()) {
        LOGE("Invalid parameter, pkgName is empty.");
        return;
    }
    LOGI("PkgName %{public}s.", pkgName.c_str());
    std::lock_guard<std::mutex> lock(appIdMapLock_);
    if (appIdMap_.find(pkgName) == appIdMap_.end()) {
        LOGE("AppIdMap not find pkgName.");
        return;
    }
    appIdMap_.erase(pkgName);
}

int32_t AppManager::GetAppIdByPkgName(const std::string &pkgName, std::string &appId)
{
    if (pkgName.empty()) {
        LOGE("Invalid parameter, pkgName is empty.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    LOGD("PkgName %{public}s.", pkgName.c_str());
    std::lock_guard<std::mutex> lock(appIdMapLock_);
    if (appIdMap_.find(pkgName) == appIdMap_.end()) {
        LOGD("AppIdMap not find pkgName.");
        return ERR_DM_FAILED;
    }
    appId = appIdMap_[pkgName];
    return DM_OK;
}

bool AppManager::GetBundleManagerProxy(sptr<AppExecFwk::IBundleMgr> &bundleManager)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        LOGE("GetBundleManagerProxy Failed to get system ability mgr.");
        return false;
    }
    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        LOGE("GetBundleManagerProxy Failed to get bundle manager service.");
        return false;
    }
    bundleManager = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (bundleManager == nullptr) {
        LOGE("bundleManager is nullptr");
        return false;
    }
    return true;
}

bool AppManager::IsSystemSA()
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

int32_t AppManager::GetCallerName(bool isSystemSA, std::string &callerName)
{
    AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    if (tokenCaller == 0) {
        LOGE("GetCallingTokenID error.");
        return ERR_DM_FAILED;
    }
    LOGI("tokenCaller ID == %{public}s", GetAnonyInt32(tokenCaller).c_str());
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
        LOGE("failed, unsupported process.");
        return ERR_DM_FAILED;
    }
    return DM_OK;
}

int32_t AppManager::GetNativeTokenIdByName(std::string &processName, int64_t &tokenId)
{
    AccessTokenID nativeTokenId = AccessTokenKit::GetNativeTokenId(processName);
    if (nativeTokenId == INVALID_TOKENID) {
        LOGE("GetNativeTokenId failed.");
        return ERR_DM_FAILED;
    }
    tokenId = static_cast<int64_t>(nativeTokenId);
    return DM_OK;
}

int32_t AppManager::GetHapTokenIdByName(int32_t userId, std::string &bundleName, int32_t instIndex, int64_t &tokenId)
{
    auto hapTokenId = AccessTokenKit::GetHapTokenID(userId, bundleName, instIndex);
    if (hapTokenId == 0) {
        LOGE("GetHapTokenId failed.");
        return ERR_DM_FAILED;
    }
    tokenId = static_cast<int64_t>(hapTokenId);
    return DM_OK;
}

int32_t AppManager::GetCallerProcessName(std::string &processName)
{
    AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    if (tokenCaller == 0) {
        LOGE("GetCallerProcessName GetCallingTokenID error.");
        return ERR_DM_FAILED;
    }
    LOGI("GetCallerProcessName::tokenCaller ID == %{public}s", GetAnonyInt32(tokenCaller).c_str());
    ATokenTypeEnum tokenTypeFlag = AccessTokenKit::GetTokenTypeFlag(tokenCaller);
    if (tokenTypeFlag == ATokenTypeEnum::TOKEN_HAP) {
        HapTokenInfo tokenInfo;
        if (AccessTokenKit::GetHapTokenInfo(tokenCaller, tokenInfo) != EOK) {
            LOGE("GetHapTokenInfo failed.");
            return ERR_DM_FAILED;
        }
        processName = std::move(tokenInfo.bundleName);
        uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
        if (!OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
            LOGE("GetCallerProcessName %{public}s not system hap.", processName.c_str());
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

    LOGI("Get process name: %{public}s success.", processName.c_str());
    return DM_OK;
}
} // namespace DistributedHardware
} // namespace OHOS
