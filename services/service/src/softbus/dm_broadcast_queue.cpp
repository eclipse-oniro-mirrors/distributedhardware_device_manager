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

#include "dm_broadcast_queue.h"

#include <pthread.h>

#include "dm_constants.h"
#include "dm_log.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
constexpr const char *BROADCAST_QUEUE_THREAD = "dm_broadcast_queue";
constexpr auto BROADCAST_INTERVAL = std::chrono::seconds(5);
}

DM_IMPLEMENT_SINGLE_INSTANCE(DmBroadcastQueue);

void DmBroadcastQueue::SetSender(Sender sender)
{
    std::lock_guard<std::mutex> lock(mutex_);
    sender_ = sender;
}

void DmBroadcastQueue::Push(const std::string &msg)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(msg);
    }
    Start();
    cv_.notify_one();
}

void DmBroadcastQueue::Start()
{
    bool expected = false;
    if (!started_.compare_exchange_strong(expected, true)) {
        return;
    }
    running_.store(true);
    worker_ = std::thread(&DmBroadcastQueue::ProcessLoop, this);
    if (pthread_setname_np(worker_.native_handle(), BROADCAST_QUEUE_THREAD) != 0) {
        LOGE("Failed to set thread name.");
    }
    LOGI("DmBroadcastQueue started.");
}

void DmBroadcastQueue::Stop()
{
    if (!started_.exchange(false)) {
        return;
    }
    running_.store(false);
    cv_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
    std::lock_guard<std::mutex> lock(mutex_);
    std::queue<std::string> empty;
    queue_.swap(empty);
    hasSent_ = false;
    lastSendTime_ = std::chrono::steady_clock::time_point();
    LOGI("DmBroadcastQueue stopped.");
}

void DmBroadcastQueue::ProcessLoop()
{
    LOGI("DmBroadcastQueue worker started.");
    while (running_.load()) {
        std::string msg;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this]() { return !queue_.empty() || !running_.load(); });
            if (!running_.load()) {
                break;
            }
            if (queue_.empty()) {
                continue;
            }
            msg = queue_.front();
            queue_.pop();
        }
        if (hasSent_) {
            auto elapsed = std::chrono::steady_clock::now() - lastSendTime_;
            if (elapsed < BROADCAST_INTERVAL) {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait_for(lock, BROADCAST_INTERVAL - elapsed,
                    [this]() { return !running_.load(); });
            }
            if (!running_.load()) {
                break;
            }
        }
        Sender sender;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            sender = sender_;
        }
        if (!sender) {
            LOGE("sender is not set, drop msg.");
            continue;
        }
        int32_t ret = sender(msg);
        if (ret != DM_OK) {
            LOGE("send acl changed broadcast failed, ret: %{public}d.", ret);
        }
        lastSendTime_ = std::chrono::steady_clock::now();
        hasSent_ = true;
    }
    LOGI("DmBroadcastQueue worker exited.");
}
} // namespace DistributedHardware
} // namespace OHOS
