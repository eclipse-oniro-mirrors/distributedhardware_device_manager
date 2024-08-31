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

#include "dm_account_common_event.h"

#include <pthread.h>
#include <thread>

#include "common_event_support.h"
#include "dm_anonymous.h"
#include "dm_constants.h"
#include "dm_log.h"
#if !(defined(__LITEOS_M__) || defined(LITE_DEVICE))
#include "dm_thread_manager.h"
#endif
#include "iservice_registry.h"
#include "multiple_user_connector.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DistributedHardware {
using OHOS::EventFwk::MatchingSkills;
using OHOS::EventFwk::CommonEventManager;

constexpr const char* DEAL_THREAD = "account_common_event";
constexpr int32_t MAX_TRY_TIMES = 3;

std::vector<std::string> DmAccountEventSubscriber::GetSubscriberEventNameVec() const
{
    return eventNameVec_;
}

DmAccountCommonEventManager::~DmAccountCommonEventManager()
{
    DmAccountCommonEventManager::UnsubscribeAccountCommonEvent();
}

bool DmAccountCommonEventManager::SubscribeAccountCommonEvent(const std::vector<std::string> &eventNameVec,
    const AccountEventCallback &callback)
{
    if (eventNameVec.empty() || callback == nullptr) {
        LOGE("eventNameVec is empty or callback is nullptr.");
        return false;
    }
    std::lock_guard<std::mutex> locker(evenSubscriberMutex_);
    if (eventValidFlag_) {
        LOGE("failed to subscribe account commom eventName size: %{public}zu", eventNameVec.size());
        return false;
    }

    MatchingSkills matchingSkills;
    for (auto &item : eventNameVec) {
        matchingSkills.AddEvent(item);
    }
    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriber_ = std::make_shared<DmAccountEventSubscriber>(subscriberInfo, callback, eventNameVec);
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        LOGE("samgrProxy is nullptr");
        subscriber_ = nullptr;
        return false;
    }
    statusChangeListener_ = new (std::nothrow) SystemAbilityStatusChangeListener(subscriber_);
    if (statusChangeListener_ == nullptr) {
        LOGE("statusChangeListener_ is nullptr");
        subscriber_ = nullptr;
        return false;
    }
    while (counter_ != MAX_TRY_TIMES) {
        if (samgrProxy->SubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, statusChangeListener_) == ERR_OK) {
            LOGI("SubscribeAccountEvent success.");
            counter_ = 0;
            break;
        }
        if (++counter_ == MAX_TRY_TIMES) {
            LOGI("SubscribeAccountEvent failed.");
        }
        sleep(1);
    }
    eventNameVec_ = eventNameVec;
    eventValidFlag_ = true;
    LOGI("success to subscribe account commom event name size: %{public}zu", eventNameVec.size());
    return true;
}

bool DmAccountCommonEventManager::UnsubscribeAccountCommonEvent()
{
    std::lock_guard<std::mutex> locker(evenSubscriberMutex_);
    if (!eventValidFlag_) {
        LOGE("failed to unsubscribe account commom event name size: %{public}zu because event is invalid.",
            eventNameVec_.size());
        return false;
    }
    if (subscriber_ != nullptr) {
        LOGI("start to unsubscribe account commom event name size: %{public}zu", eventNameVec_.size());
        if (!CommonEventManager::UnSubscribeCommonEvent(subscriber_)) {
            LOGE("failed to unsubscribe account commom event name size: %{public}zu", eventNameVec_.size());
            return false;
        }
        LOGI("success to unsubscribe account commom event name size: %{public}zu", eventNameVec_.size());
        subscriber_ = nullptr;
    }
    if (statusChangeListener_ != nullptr) {
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            LOGE("samgrProxy is nullptr");
            return false;
        }
        int32_t ret = samgrProxy->UnSubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, statusChangeListener_);
        if (ret != ERR_OK) {
            LOGE("failed to unsubscribe system ability COMMON_EVENT_SERVICE_ID ret:%{public}d", ret);
            return false;
        }
        statusChangeListener_ = nullptr;
    }

    LOGI("success to unsubscribe account commom event name size: %{public}zu", eventNameVec_.size());
    eventValidFlag_ = false;
    return true;
}

void DmAccountEventSubscriber::OnReceiveEvent(const CommonEventData &data)
{
    std::string receiveEvent = data.GetWant().GetAction();
    LOGI("Received account event: %{public}s", receiveEvent.c_str());
    int32_t userId = data.GetCode();
    bool accountValiedEvent = false;
    if (receiveEvent == EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED ||
        receiveEvent == EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        userId = data.GetCode();
        accountValiedEvent = true;
    }
    if (receiveEvent == EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT ||
        receiveEvent == EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGIN) {
        userId = data.GetWant().GetIntParam("userId", 0);
        accountValiedEvent = true;
    }
    if (userId <= 0 || !accountValiedEvent) {
        LOGE("Invalied account type event.");
        return;
    }
#if !(defined(__LITEOS_M__) || defined(LITE_DEVICE))
    ThreadManager::GetInstance().Submit(DEAL_THREAD, [=]() { callback_(userId, receiveEvent); });
#else
    std::thread dealThread([=]() { callback_(userId, receiveEvent); });
    int32_t ret = pthread_setname_np(dealThread.native_handle(), DEAL_THREAD);
    if (ret != DM_OK) {
        LOGE("dealThread setname failed.");
    }
    dealThread.detach();
#endif
}

void DmAccountCommonEventManager::SystemAbilityStatusChangeListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    LOGI("systemAbility is added with said: %{public}d.", systemAbilityId);
    if (systemAbilityId != COMMON_EVENT_SERVICE_ID) {
        return;
    }
    if (changeSubscriber_ == nullptr) {
        LOGE("failed to subscribe account commom event because changeSubscriber_ is nullptr.");
        return;
    }
    std::vector<std::string> eventNameVec = changeSubscriber_->GetSubscriberEventNameVec();
    LOGI("start to subscribe account commom eventName: %{public}zu", eventNameVec.size());
    if (!CommonEventManager::SubscribeCommonEvent(changeSubscriber_)) {
        LOGE("failed to subscribe account commom event: %{public}zu", eventNameVec.size());
    }
    int32_t userId = MultipleUserConnector::GetCurrentAccountUserID();
    std::string accountId = MultipleUserConnector::GetOhosAccountId();
    LOGI("after subscribe account event accountId: %{public}s, userId: %{public}s",
        GetAnonyString(accountId).c_str(), GetAnonyInt32(userId).c_str());
    if (userId > 0) {
        MultipleUserConnector::SetSwitchOldUserId(userId);
        MultipleUserConnector::SetSwitchOldAccountId(accountId);
    }
}

void DmAccountCommonEventManager::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    LOGI("systemAbility is removed with said: %{public}d.", systemAbilityId);
}
} // namespace DistributedHardware
} // namespace OHOS
