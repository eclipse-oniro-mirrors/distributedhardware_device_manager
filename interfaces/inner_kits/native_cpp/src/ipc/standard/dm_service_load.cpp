/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "dm_service_load.h"

#include <chrono>

#include "dm_error_type.h"
#include "dm_log.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
constexpr int32_t DM_SERVICE_LOAD_TIMEOUT_SECONDS = 5;
}

DM_IMPLEMENT_SINGLE_INSTANCE(DmServiceLoad);

int32_t DmServiceLoad::LoadDMService(void)
{
    std::unique_lock<std::mutex> autoLock(dmServiceLoadLock_);
    LOGD("LoadDMService enter, loading:%{public}d, loadFailed:%{public}d",
        isDMServiceLoading_.load(), loadFailed_.load());
    if (isDMServiceLoading_.load()) {
        LOGI("DM service is loading.");
        LOGD("DM service is loading, wait finish.");
        bool loadDone = dmServiceLoadCv_.wait_for(autoLock,
            std::chrono::seconds(DM_SERVICE_LOAD_TIMEOUT_SECONDS),
            [this](){ return !isDMServiceLoading_.load(); });
        LOGD("LoadDMService wait done (already-loading), loadDone:%{public}d, loadFailed:%{public}d",
            loadDone, loadFailed_.load());
        return (loadDone && !loadFailed_.load()) ? DM_OK : ERR_DM_INIT_FAILED;
    }
    LOGI("start");
    LOGD("LoadDMService trigger load");
    isDMServiceLoading_.store(true);
    loadFailed_.store(false);
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        ResetLoadState();
        LOGE("failed to get system ability mgr.");
        return ERR_DM_POINT_NULL;
    }
    sptr<DMLoadCallback> dmLoadCallback_(new DMLoadCallback());
    int32_t ret = samgr->LoadSystemAbility(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID, dmLoadCallback_);
    if (ret != DM_OK) {
        ResetLoadState();
        LOGE("Failed to Load DM service, ret code:%{public}d", ret);
        return ret;
    }
    if (!dmServiceLoadCv_.wait_for(autoLock, std::chrono::seconds(DM_SERVICE_LOAD_TIMEOUT_SECONDS),
        [this](){ return !isDMServiceLoading_.load(); })) {
        LOGE("LoadDMService wait timeout, reset loading flag");
        ResetLoadState();
        return ERR_DM_INIT_FAILED;
    }
    LOGD("LoadDMService wait done (new-load), loading:%{public}d, loadFailed:%{public}d",
        isDMServiceLoading_.load(), loadFailed_.load());
    return loadFailed_.load() ? ERR_DM_INIT_FAILED : DM_OK;
}

void DmServiceLoad::ResetLoadState(void)
{
    isDMServiceLoading_.store(false);
    loadFailed_.store(true);
    dmServiceLoadCv_.notify_all();
}

void DmServiceLoad::SetLoadFinish(void)
{
    std::lock_guard<std::mutex> autoLock(dmServiceLoadLock_);
    isDMServiceLoading_.store(false);
    LOGD("SetLoadFinish, notify load done, loadFailed:%{public}d", loadFailed_.load());
    dmServiceLoadCv_.notify_all();
}

void DmServiceLoad::SetLoadFailed(void)
{
    std::lock_guard<std::mutex> autoLock(dmServiceLoadLock_);
    isDMServiceLoading_.store(false);
    loadFailed_.store(true);
    LOGD("SetLoadFailed, notify load done, loadFailed:%{public}d", loadFailed_.load());
    dmServiceLoadCv_.notify_all();
}

void DMLoadCallback::OnLoadSystemAbilitySuccess(int32_t systemAbilityId,
    const sptr<IRemoteObject> &remoteObject)
{
    LOGI("Load DM service success remoteObject result:%{public}s", (remoteObject != nullptr) ? "true" : "false");
    DmServiceLoad::GetInstance().SetLoadFinish();
    if (remoteObject == nullptr) {
        LOGE("remoteObject is nullptr");
        return;
    }
}

void DMLoadCallback::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    LOGE("Load DM service failed.");
    DmServiceLoad::GetInstance().SetLoadFailed();
}
} // namespace DistributedHardware
} // namespace OHOS
