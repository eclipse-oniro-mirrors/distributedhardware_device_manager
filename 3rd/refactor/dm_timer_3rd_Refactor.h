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
#ifndef DM_TIMER_3RD_REFACTOR_H
#define DM_TIMER_3RD_REFACTOR_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>
#include <unordered_map>

#include "ffrt.h"

namespace OHOS {
namespace DistributedHardware {

using TimerCallbackRefactor = std::function<void(std::string name)>;

class DmTimer3rdRefactor {
public:
    DmTimer3rdRefactor();
    ~DmTimer3rdRefactor();

    int32_t StartTimer(const std::string &name, int32_t timeOut, TimerCallbackRefactor callback);
    int32_t DeleteTimer(const std::string &timerName);
    int32_t DeleteAll();

private:
    mutable ffrt::mutex timerMutex_;
    std::unordered_map<std::string, ffrt::task_handle> timerVec_ = {};
    std::shared_ptr<ffrt::queue> queue_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif
