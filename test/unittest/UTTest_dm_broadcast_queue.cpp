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

#include "UTTest_dm_broadcast_queue.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "dm_broadcast_queue.h"
#include "dm_constants.h"

namespace OHOS {
namespace DistributedHardware {

void DmBroadcastQueueTest::SetUpTestCase() {}
void DmBroadcastQueueTest::TearDownTestCase() {}
void DmBroadcastQueueTest::SetUp() {}
void DmBroadcastQueueTest::TearDown()
{
    DmBroadcastQueue::GetInstance().Stop();
}

namespace {
using SteadyTime = std::chrono::steady_clock::time_point;

struct FakeSender {
    std::mutex mtx;
    std::condition_variable cv;
    std::vector<std::string> msgs;
    std::vector<SteadyTime> times;
    std::atomic<int32_t> ret{DM_OK};

    int32_t Call(const std::string &msg)
    {
        {
            std::lock_guard<std::mutex> lock(mtx);
            msgs.push_back(msg);
            times.push_back(std::chrono::steady_clock::now());
        }
        cv.notify_all();
        return ret.load();
    }

    size_t Count()
    {
        std::lock_guard<std::mutex> lock(mtx);
        return msgs.size();
    }

    std::string MsgAt(size_t i)
    {
        std::lock_guard<std::mutex> lock(mtx);
        return (i < msgs.size()) ? msgs[i] : std::string();
    }

    SteadyTime TimeAt(size_t i)
    {
        std::lock_guard<std::mutex> lock(mtx);
        return (i < times.size()) ? times[i] : SteadyTime();
    }

    bool WaitUntil(size_t n, std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lock(mtx);
        return cv.wait_for(lock, timeout, [this, n]() { return msgs.size() >= n; });
    }

    void Reset()
    {
        std::lock_guard<std::mutex> lock(mtx);
        msgs.clear();
        times.clear();
    }
};

DmBroadcastQueue::Sender MakeSender(std::shared_ptr<FakeSender> fake)
{
    return [fake](const std::string &msg) -> int32_t { return fake->Call(msg); };
}

HWTEST_F(DmBroadcastQueueTest, FirstSendIsImmediate_001, testing::ext::TestSize.Level1)
{
    auto fake = std::make_shared<FakeSender>();
    DmBroadcastQueue::GetInstance().SetSender(MakeSender(fake));
    auto t0 = std::chrono::steady_clock::now();
    DmBroadcastQueue::GetInstance().Push("msg-1");
    ASSERT_TRUE(fake->WaitUntil(1, std::chrono::seconds(2)));
    auto gap = std::chrono::duration_cast<std::chrono::milliseconds>(fake->TimeAt(0) - t0);
    ASSERT_EQ(fake->MsgAt(0), "msg-1");
    ASSERT_LT(gap.count(), 2000);
}

HWTEST_F(DmBroadcastQueueTest, SecondSendAtLeast5sAfterFirst_001, testing::ext::TestSize.Level2)
{
    auto fake = std::make_shared<FakeSender>();
    DmBroadcastQueue::GetInstance().SetSender(MakeSender(fake));
    DmBroadcastQueue::GetInstance().Push("msg-a");
    DmBroadcastQueue::GetInstance().Push("msg-b");
    ASSERT_TRUE(fake->WaitUntil(2, std::chrono::seconds(10)));
    auto gap = std::chrono::duration_cast<std::chrono::milliseconds>(
        fake->TimeAt(1) - fake->TimeAt(0));
    ASSERT_GE(gap.count(), 5000);
    ASSERT_EQ(fake->MsgAt(0), "msg-a");
    ASSERT_EQ(fake->MsgAt(1), "msg-b");
}

HWTEST_F(DmBroadcastQueueTest, StopInterruptsPendingWait_001, testing::ext::TestSize.Level1)
{
    auto fake = std::make_shared<FakeSender>();
    DmBroadcastQueue::GetInstance().SetSender(MakeSender(fake));
    DmBroadcastQueue::GetInstance().Push("first");
    ASSERT_TRUE(fake->WaitUntil(1, std::chrono::seconds(2)));
    DmBroadcastQueue::GetInstance().Push("pending");
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    auto t0 = std::chrono::steady_clock::now();
    DmBroadcastQueue::GetInstance().Stop();
    auto t1 = std::chrono::steady_clock::now();
    auto stopGap = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0);
    ASSERT_LT(stopGap.count(), 1000);
    ASSERT_EQ(fake->Count(), 1u);
}

HWTEST_F(DmBroadcastQueueTest, RestartAfterStopResetsTiming_001, testing::ext::TestSize.Level1)
{
    auto fake = std::make_shared<FakeSender>();
    DmBroadcastQueue::GetInstance().SetSender(MakeSender(fake));
    DmBroadcastQueue::GetInstance().Push("round1");
    ASSERT_TRUE(fake->WaitUntil(1, std::chrono::seconds(2)));
    ASSERT_EQ(fake->MsgAt(0), "round1");
    DmBroadcastQueue::GetInstance().Stop();

    fake->Reset();
    DmBroadcastQueue::GetInstance().SetSender(MakeSender(fake));
    auto t0 = std::chrono::steady_clock::now();
    DmBroadcastQueue::GetInstance().Push("round2");
    ASSERT_TRUE(fake->WaitUntil(1, std::chrono::seconds(2)));
    auto gap = std::chrono::duration_cast<std::chrono::milliseconds>(fake->TimeAt(0) - t0);
    ASSERT_EQ(fake->MsgAt(0), "round2");
    ASSERT_LT(gap.count(), 2000);
    DmBroadcastQueue::GetInstance().Stop();
    DmBroadcastQueue::GetInstance().Stop();
}

HWTEST_F(DmBroadcastQueueTest, StopWithoutStartIsNoop_001, testing::ext::TestSize.Level1)
{
    DmBroadcastQueue::GetInstance().Stop();
    DmBroadcastQueue::GetInstance().Stop();
    ASSERT_TRUE(true);
}
} // namespace
} // namespace DistributedHardware
} // namespace OHOS
