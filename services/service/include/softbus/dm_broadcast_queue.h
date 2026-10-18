/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_DM_BROADCAST_QUEUE_H
#define OHOS_DM_BROADCAST_QUEUE_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

#include "dm_single_instance.h"

namespace OHOS {
namespace DistributedHardware {

class DmBroadcastQueue {
    DM_DECLARE_SINGLE_INSTANCE(DmBroadcastQueue);
public:
    using Sender = std::function<int32_t(const std::string &)>;

    void SetSender(Sender sender);
    void Push(const std::string &msg);
    void Start();
    void Stop();

private:
    void ProcessLoop();

    std::queue<std::string> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::thread worker_;
    std::atomic<bool> running_ = {false};
    std::atomic<bool> started_ = {false};
    std::chrono::steady_clock::time_point lastSendTime_;
    bool hasSent_ = false;
    Sender sender_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_BROADCAST_QUEUE_H
