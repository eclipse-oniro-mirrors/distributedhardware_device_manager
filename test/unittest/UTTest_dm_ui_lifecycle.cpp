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
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <cstdlib>
#include <mutex>
#include <set>
#include <thread>
#include <vector>
#include <gtest/gtest.h>
#include "ability_connect_callback_interface.h"
#include "dm_dialog_client.h"
#include "dm_ui_api.h"
#include "ffrt.h"

namespace OHOS::DistributedHardware {
bool ResetUiStateForTest();
}

using namespace OHOS;
using namespace OHOS::DistributedHardware;
namespace {
struct Context {
    DmUiSessionHost host;
    sptr<AAFwk::IAbilityConnection> connection;
};
constexpr uint64_t CLOSE_TIMEOUT_US = 5000000;
constexpr int32_t DISCONNECT_ERROR = -2;
constexpr size_t MAX_DEFERRED_REQUESTS = 16;
std::atomic<int> opens {0};
std::atomic<int> closes {0};
std::atomic<int> destroys {0};
std::atomic<int> calls {0};
std::atomic<int> events {0};
std::atomic<int> inside {0};
bool failOpen = false;
bool failApi = false;
bool deferClose = false;
bool failResidentApi = false;
bool failCreate = false;
int32_t closeResult = 0;
int32_t disconnectResult = 0;
uint32_t sessionFlags = DM_UI_CAN_UNLOAD_DIALOG;
uint32_t sessionVersion = DM_UI_SESSION_API_VERSION;
bool failSessionSymbol = false;
std::atomic<int> workCalls {0};
std::atomic<int> residentCalls {0};
std::atomic<uint32_t> lastResidentOperation {DM_UI_CONFIRM};
std::atomic<bool> closeOnResidentShow {false};
std::mutex taskMutex;
std::vector<ffrt_function_header_t *> timers;
std::vector<ffrt_function_header_t *> workQueue;
std::set<Context *> contexts;
std::mutex gate;
std::condition_variable changed;
bool blockShow = false;
bool entered = false;
bool proceed = false;
bool blockWork = false;
bool workEntered = false;
bool workProceed = false;
std::vector<sptr<AAFwk::IAbilityConnection>> connections;

void *Create(const DmUiSessionHost *host, void *connection)
{
    EXPECT_EQ(host->size, sizeof(DmUiSessionHost));
    EXPECT_NE(host->submit, nullptr);
    connections.emplace_back(static_cast<AAFwk::IAbilityConnection *>(connection));
    if (failCreate) {
        return nullptr;
    }
    auto context = new Context {*host, connections.back()};
    contexts.insert(context);
    return context;
}
void RunConnectionWork(void *)
{
    ++inside;
    ++workCalls;
    {
        std::unique_lock<std::mutex> lock(gate);
        if (blockWork) {
            workEntered = true;
            changed.notify_all();
            changed.wait(lock, [] { return workProceed; });
        }
    }
    --inside;
}

int32_t Invoke(void *value, uint32_t operation, const char *, size_t)
{
    ++inside;
    ++calls;
    if (operation == DM_UI_CONFIRM) {
        std::unique_lock<std::mutex> lock(gate);
        if (blockShow) {
            entered = true;
            changed.notify_all();
            changed.wait(lock, [] { return proceed; });
        }
    }
    if (operation == DM_UI_PIN) {
        auto context = static_cast<Context *>(value);
        EXPECT_EQ(context->host.submit(context->host.generation, RunConnectionWork, value), 0);
    }
    if (operation == DM_UI_CLOSE && !deferClose && closeResult == 0) {
        static_cast<Context *>(value)->connection->OnAbilityDisconnectDone(
            AppExecFwk::ElementName(), disconnectResult);
    }
    --inside;
    return operation == DM_UI_CLOSE ? closeResult : 0;
}
void Connected(void *, void *, int32_t)
{
    ++events;
}
void Disconnected(void *value, int32_t result)
{
    ++events;
    auto context = static_cast<Context *>(value);
    if (result == 0 || result == DM_UI_TARGET_TERMINATED) {
        context->host.retire(context->host.generation);
    }
}
void Destroy(void *context)
{
    EXPECT_EQ(inside.load(), 0);
    ++destroys;
    contexts.erase(static_cast<Context *>(context));
    delete static_cast<Context *>(context);
}
DmUiSessionApi api { DM_UI_SESSION_API_VERSION, sizeof(DmUiSessionApi), DM_UI_CAN_UNLOAD_DIALOG,
    Create, Invoke, Connected, Disconnected, Destroy };
const DmUiSessionApi *GetApi()
{
    api.flags = sessionFlags;
    api.version = sessionVersion;
    return failApi ? nullptr : &api;
}
int32_t ResidentInvoke(uint32_t operation, const char *, size_t)
{
    EXPECT_EQ(inside.load(), 0);
    ++residentCalls;
    lastResidentOperation.store(operation);
    if (operation == DM_UI_CONFIRM && closeOnResidentShow.exchange(false)) {
        EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    }
    return 0;
}
const DmUiApi residentApi { DM_UI_API_VERSION, sizeof(DmUiApi), ResidentInvoke };
const DmUiApi *GetResidentApi()
{
    return failResidentApi ? nullptr : &residentApi;
}
void RunTasks(std::vector<ffrt_function_header_t *> &queue, bool execute)
{
    std::vector<ffrt_function_header_t *> tasks;
    {
        std::lock_guard<std::mutex> lock(taskMutex);
        tasks.swap(queue);
    }
    for (auto task : tasks) {
        if (execute) {
            task->exec(task);
        }
        task->destroy(task);
        std::free(task);
    }
}
void RunTimers(bool execute = true)
{
    RunTasks(timers, execute);
}
void RunWork()
{
    RunTasks(workQueue, true);
}
class DmUiLifecycle : public testing::Test {
public:
    void SetUp() override
    {
        ASSERT_TRUE(ResetUiStateForTest());
        opens = closes = destroys = calls = events = inside = residentCalls = 0;
        failOpen = failApi = failResidentApi = failCreate = deferClose = false;
        closeResult = disconnectResult = 0;
        closeOnResidentShow = false;
        sessionFlags = DM_UI_CAN_UNLOAD_DIALOG;
        sessionVersion = DM_UI_SESSION_API_VERSION;
        failSessionSymbol = false;
        workCalls = 0;
        blockWork = workEntered = workProceed = false;
        blockShow = entered = proceed = false;
    }
    void TearDown() override
    {
        RunWork();
        RunTimers(false);
        EXPECT_TRUE(ResetUiStateForTest());
        connections.clear();
        // The fixture, not the production recovery path, reclaims retained mock sessions.
        for (auto context : contexts) {
            delete context;
        }
        contexts.clear();
    }
};
}
extern "C" void *__wrap_ffrt_alloc_auto_managed_function_storage_base(ffrt_function_kind_t)
{
    return std::calloc(1, ffrt_auto_managed_function_storage_size);
}
extern "C" void __wrap_ffrt_submit_base(ffrt_function_header_t *task, const ffrt_deps_t *, const ffrt_deps_t *,
    const ffrt_task_attr_t *attr)
{
    auto delay = ffrt_task_attr_get_delay(attr);
    EXPECT_TRUE(delay == 0 || delay == CLOSE_TIMEOUT_US);
    std::lock_guard<std::mutex> lock(taskMutex);
    (delay == 0 ? workQueue : timers).push_back(task);
}
extern "C" void *__wrap_dlopen(const char *name, int)
{
    EXPECT_STREQ(name, "libdm_ui.z.so");
    ++opens;
    return failOpen ? nullptr : &opens;
}
extern "C" void *__wrap_dlsym(void *, const char *name)
{
    if (std::strcmp(name, "DmGetUiApiV1") == 0) {
        return reinterpret_cast<void *>(GetResidentApi);
    }
    EXPECT_STREQ(name, "DmGetUiSessionApiV2");
    return failSessionSymbol ? nullptr : reinterpret_cast<void *>(GetApi);
}
extern "C" void *__wrap___dlsym_time64(void *handle, const char *name)
{
    return __wrap_dlsym(handle, name);
}
extern "C" int __wrap_dlclose(void *)
{
    EXPECT_EQ(inside.load(), 0);
    ++closes;
    return 0;
}

TEST_F(DmUiLifecycle, ReleaseAndReloadWithLateAndConcurrentCallbacks)
{
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(opens.load(), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE + 1, nullptr, 0), -1);
    EXPECT_EQ(opens.load(), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, nullptr, 1), -1);
    failOpen = true;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), -1);
    failOpen = false;
    failApi = true;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), -1);
    EXPECT_EQ(closes.load(), 1);
    failApi = false;
    for (int cycle = 0; cycle < 5; ++cycle) {
        int before = closes.load();
        ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
        EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
        EXPECT_EQ(closes.load(), before + 1);
        int callbacks = events.load();
        connections.back()->OnAbilityConnectDone(AppExecFwk::ElementName(), nullptr, 0);
        connections.back()->OnAbilityDisconnectDone(AppExecFwk::ElementName(), 0);
        EXPECT_EQ(events.load(), callbacks); // Old generations cannot call unloaded code.
    }
    EXPECT_EQ(destroys.load(), 5);

    // The next show is accepted into the host queue while the old close completes.
    deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    auto closingConnection = connections.back();
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    int dispatched = calls.load();
    int before = closes.load();
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(calls.load(), dispatched);
    closingConnection->OnAbilityDisconnectDone(AppExecFwk::ElementName(), 0);
    EXPECT_EQ(closes.load(), before + 1);
    EXPECT_EQ(calls.load(), dispatched + 1);
    deferClose = false;
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);

    // A callback requests retirement while another module call is still running.
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    {
        std::lock_guard<std::mutex> lock(gate);
        blockShow = true;
        entered = false;
        proceed = false;
    }
    std::thread active([] { ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0); });
    {
        std::unique_lock<std::mutex> lock(gate);
        changed.wait(lock, [] { return entered; });
    }
    before = closes.load();
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(closes.load(), before);
    {
        std::lock_guard<std::mutex> lock(gate);
        proceed = true;
        blockShow = false;
        changed.notify_all();
    }
    active.join();
    EXPECT_EQ(closes.load(), before + 1);

    // A UI client registered for cancellation still releases native resources.
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    before = closes.load();
    DmDialogClient::GetInstance().ReleaseConfirmSession();
    EXPECT_EQ(closes.load(), before + 1);

    // PIN work is owned by the host and releases the module after closing.
    EXPECT_EQ(InvokeDmUi(DM_UI_PIN, "123456", 6), 0);
    RunWork();
    before = closes.load();
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(closes.load(), before + 1);
    DmDialogClient::GetInstance().ReleaseConfirmSession();
    EXPECT_EQ(closes.load(), before + 1);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE + 1, "{}", 2), -1);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(closes.load(), before + 1);
}

TEST_F(DmUiLifecycle, CloseFailureUsesResidentBackendWithoutDestroyOrUnload)
{
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    closeResult = DISCONNECT_ERROR;
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), DISCONNECT_ERROR);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(residentCalls.load(), 1);
    EXPECT_EQ(destroys.load(), 0);
    EXPECT_EQ(closes.load(), 0);
    EXPECT_EQ(contexts.size(), 1U);
    for (size_t index = 0; index < MAX_DEFERRED_REQUESTS; ++index) {
        EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
        EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    }
    EXPECT_EQ(contexts.size(), 1U);
    EXPECT_EQ(opens.load(), 1);
}

TEST_F(DmUiLifecycle, MissingDisconnectCallbackReplaysPendingOnTimeout)
{
    deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(residentCalls.load(), 0);
    RunTimers();
    EXPECT_EQ(residentCalls.load(), 1);
    EXPECT_EQ(closes.load(), 0);
    EXPECT_EQ(destroys.load(), 0);
}

TEST_F(DmUiLifecycle, FailedDisconnectCallbackRecoversImmediately)
{
    disconnectResult = DISCONNECT_ERROR;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(residentCalls.load(), 1);
    EXPECT_EQ(closes.load(), 0);
    EXPECT_EQ(destroys.load(), 0);
}

TEST_F(DmUiLifecycle, StaleWatchdogCannotRecoverNewGeneration)
{
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    ASSERT_EQ(closes.load(), 1);
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    auto currentConnection = connections.back();
    std::vector<ffrt_function_header_t *> staleTimers;
    {
        std::lock_guard<std::mutex> lock(taskMutex);
        staleTimers.swap(timers);
    }
    EXPECT_EQ(staleTimers.size(), 1U);
    deferClose = true;
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    // The stale timeout must not recover a successor that is also closing.
    RunTasks(staleTimers, true);
    currentConnection->OnAbilityDisconnectDone(AppExecFwk::ElementName(), 0);
    EXPECT_EQ(closes.load(), 2);
    EXPECT_EQ(destroys.load(), 2);
    RunTimers();
    deferClose = false;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(residentCalls.load(), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(closes.load(), 3);
}

TEST_F(DmUiLifecycle, RepeatedCloseCancelsDeferredDisplay)
{
    deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    DmDialogClient::GetInstance().ReleaseConfirmSession();
    RunTimers();
    EXPECT_EQ(residentCalls.load(), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(residentCalls.load(), 1);
}

TEST_F(DmUiLifecycle, QueueCapacityIsBoundedAndRecoveryDrainsIt)
{
    deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    for (size_t index = 0; index < MAX_DEFERRED_REQUESTS; ++index) {
        EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    }
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), -1);
    RunTimers();
    EXPECT_EQ(residentCalls.load(), static_cast<int>(MAX_DEFERRED_REQUESTS));
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
}

TEST_F(DmUiLifecycle, RecoveryWaitsForExecutingModuleCall)
{
    deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    {
        std::lock_guard<std::mutex> lock(gate);
        blockShow = true;
    }
    std::thread running([] { EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0); });
    {
        std::unique_lock<std::mutex> lock(gate);
        changed.wait(lock, [] { return entered; });
    }
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    RunTimers();
    EXPECT_EQ(residentCalls.load(), 0);
    EXPECT_EQ(closes.load(), 0);
    {
        std::lock_guard<std::mutex> lock(gate);
        blockShow = false;
        proceed = true;
        changed.notify_all();
    }
    running.join();
    EXPECT_EQ(residentCalls.load(), 1);
    EXPECT_EQ(destroys.load(), 0);
}

TEST_F(DmUiLifecycle, LateCallbackCannotUnloadResidentBackend)
{
    deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    auto old = connections.back();
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    RunTimers();
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    old->OnAbilityDisconnectDone(AppExecFwk::ElementName(), 0);
    int before = events.load();
    old->OnAbilityConnectDone(AppExecFwk::ElementName(), nullptr, 0);
    EXPECT_EQ(events.load(), before);
    EXPECT_EQ(closes.load(), 0);
    EXPECT_EQ(destroys.load(), 0);
    DmDialogClient::GetInstance().ReleaseConfirmSession();
    EXPECT_EQ(lastResidentOperation.load(), DM_UI_CLOSE);
    int callsBeforeInvalid = residentCalls.load();
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE + 1, "{}", 2), -1);
    EXPECT_EQ(residentCalls.load(), callsBeforeInvalid);
}

TEST_F(DmUiLifecycle, RegisteredUiCloseFailureAlsoRecovers)
{
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    closeResult = DISCONNECT_ERROR;
    DmDialogClient::GetInstance().ReleaseConfirmSession();
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(residentCalls.load(), 1);
    EXPECT_EQ(destroys.load(), 0);
}

TEST_F(DmUiLifecycle, MissingResidentApiAndCreateFailureCanRetry)
{
    failResidentApi = true;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), -1);
    failResidentApi = false;
    failCreate = true;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), -1);
    failCreate = false;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(destroys.load(), 1);
}

TEST_F(DmUiLifecycle, MissingUnloadCapabilityIsRejectedAndCanRetry)
{
    sessionFlags = 0;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), -1);
    EXPECT_EQ(opens.load(), 1);
    EXPECT_EQ(closes.load(), 1);
    EXPECT_EQ(destroys.load(), 0);
    EXPECT_EQ(calls.load(), 0);
    EXPECT_TRUE(contexts.empty());
    sessionFlags = DM_UI_CAN_UNLOAD_DIALOG;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(destroys.load(), 1);
    EXPECT_EQ(closes.load(), 2);
    RunTimers();
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(opens.load(), 3);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(destroys.load(), 2);
    EXPECT_EQ(closes.load(), 3);
    EXPECT_EQ(residentCalls.load(), 0);
}

namespace {
void VerifySuccessfulDisconnectBeforeDrain(bool acknowledgeBeforeTimeout)
{
    deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    auto connection = connections.back();
    {
        std::lock_guard<std::mutex> lock(gate);
        blockShow = true;
    }
    std::thread running([] { EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0); });
    {
        std::unique_lock<std::mutex> lock(gate);
        changed.wait(lock, [] { return entered; });
    }
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    if (acknowledgeBeforeTimeout) {
        connection->OnAbilityDisconnectDone(AppExecFwk::ElementName(), 0);
        RunTimers();
    } else {
        RunTimers();
        connection->OnAbilityDisconnectDone(AppExecFwk::ElementName(), 0);
    }
    EXPECT_EQ(destroys.load(), 0);
    EXPECT_EQ(closes.load(), 0);
    {
        std::lock_guard<std::mutex> lock(gate);
        blockShow = false;
        proceed = true;
        changed.notify_all();
    }
    running.join();
    EXPECT_EQ(destroys.load(), 1);
    EXPECT_EQ(closes.load(), 1);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(residentCalls.load(), 0);
    deferClose = false;
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(closes.load(), 2);
}

TEST_F(DmUiLifecycle, TargetTerminationReleasesWithoutExplicitClose)
{
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    auto old = connections.back();
    old->OnAbilityDisconnectDone(AppExecFwk::ElementName(), DM_UI_TARGET_TERMINATED);
    EXPECT_EQ(destroys.load(), 1);
    EXPECT_EQ(closes.load(), 1);
    EXPECT_EQ(residentCalls.load(), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_INPUT, "{}", 2), 0);
    old->OnAbilityDisconnectDone(AppExecFwk::ElementName(), DM_UI_TARGET_TERMINATED);
    EXPECT_EQ(destroys.load(), 1);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(destroys.load(), 2);
}

} // namespace

TEST_F(DmUiLifecycle, SuccessfulDisconnectBeforeTimeoutKeepsReleasePath)
{
    VerifySuccessfulDisconnectBeforeDrain(true);
}

TEST_F(DmUiLifecycle, SuccessfulDisconnectCancelsRecoveryBeforeLastCallReturns)
{
    VerifySuccessfulDisconnectBeforeDrain(false);
}

TEST_F(DmUiLifecycle, CloseDuringReplayCancelsRemainingRequests)
{
    deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    constexpr size_t REQUESTS_TO_CANCEL = 3;
    for (size_t index = 0; index < REQUESTS_TO_CANCEL; ++index) {
        EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    }
    closeOnResidentShow = true;
    RunTimers();
    // The first show and its reentrant close run; later, stale shows are cancelled.
    EXPECT_EQ(residentCalls.load(), 2);
    EXPECT_EQ(lastResidentOperation.load(), DM_UI_CLOSE);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(residentCalls.load(), 3);
    EXPECT_EQ(closes.load(), 0);
}

TEST_F(DmUiLifecycle, AllDialogTypesReleaseAndReload)
{
    constexpr uint32_t OPERATIONS[] = { DM_UI_CONFIRM, DM_UI_SERVICE_CONFIRM, DM_UI_PIN, DM_UI_INPUT };
    int expected = 0;
    for (uint32_t operation : OPERATIONS) {
        EXPECT_EQ(InvokeDmUi(operation, "synthetic", 9), 0);
        RunWork();
        DmDialogClient::GetInstance().ReleaseSession(operation);
        EXPECT_EQ(closes.load(), ++expected);
        EXPECT_EQ(destroys.load(), expected);
    }
    EXPECT_EQ(workCalls.load(), 1);
}

TEST_F(DmUiLifecycle, QueuedPinWorkKeepsLeaseUntilCancelledTaskReturns)
{
    ASSERT_EQ(InvokeDmUi(DM_UI_PIN, "123456", 6), 0);
    EXPECT_EQ(workCalls.load(), 0);
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_PIN);
    EXPECT_EQ(destroys.load(), 0);
    EXPECT_EQ(closes.load(), 0);
    RunWork();
    EXPECT_EQ(workCalls.load(), 0);
    EXPECT_EQ(destroys.load(), 1);
    EXPECT_EQ(closes.load(), 1);
}

TEST_F(DmUiLifecycle, ExecutingPinWorkPreventsUnload)
{
    blockWork = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_PIN, "123456", 6), 0);
    std::thread running([] { RunWork(); });
    {
        std::unique_lock<std::mutex> lock(gate);
        changed.wait(lock, [] { return workEntered; });
    }
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_PIN);
    EXPECT_EQ(destroys.load(), 0);
    EXPECT_EQ(closes.load(), 0);
    RunTimers();
    {
        std::lock_guard<std::mutex> lock(gate);
        workProceed = true;
        changed.notify_all();
    }
    running.join();
    EXPECT_EQ(workCalls.load(), 1);
    EXPECT_EQ(destroys.load(), 1);
    EXPECT_EQ(closes.load(), 1);
    EXPECT_EQ(residentCalls.load(), 0);
}

TEST_F(DmUiLifecycle, DifferentDialogCancellationCannotCloseCurrentDialog)
{
    ASSERT_EQ(InvokeDmUi(DM_UI_INPUT, "synthetic", 9), 0);
    int dispatched = calls.load();
    DmDialogClient::GetInstance().ReleaseConfirmSession();
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_PIN);
    EXPECT_EQ(calls.load(), dispatched);
    EXPECT_EQ(closes.load(), 0);
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_INPUT);
    EXPECT_EQ(closes.load(), 1);
    ASSERT_EQ(InvokeDmUi(DM_UI_SERVICE_CONFIRM, "{}", 2), 0);
    DmDialogClient::GetInstance().ReleaseConfirmSession();
    EXPECT_EQ(closes.load(), 2);
}

TEST_F(DmUiLifecycle, TypedCancelPreservesOtherQueuedDialogs)
{
    deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    auto connection = connections.back();
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    int dispatched = calls.load();
    EXPECT_EQ(InvokeDmUi(DM_UI_INPUT, "synthetic", 9), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_SERVICE_CONFIRM, "{}", 2), 0);
    DmDialogClient::GetInstance().ReleaseConfirmSession();
    connection->OnAbilityDisconnectDone(AppExecFwk::ElementName(), 0);
    EXPECT_EQ(calls.load(), dispatched + 1);
    DmDialogClient::GetInstance().ReleaseConfirmSession();
    EXPECT_EQ(calls.load(), dispatched + 1);
    deferClose = false;
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_INPUT);
    EXPECT_EQ(closes.load(), 2);
}

TEST_F(DmUiLifecycle, SupersededPinWorkDoesNotConnectAfterInput)
{
    ASSERT_EQ(InvokeDmUi(DM_UI_PIN, "123456", 6), 0);
    ASSERT_EQ(InvokeDmUi(DM_UI_INPUT, "synthetic", 9), 0);
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_PIN);
    RunWork();
    EXPECT_EQ(workCalls.load(), 0);
    EXPECT_EQ(closes.load(), 0);
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_INPUT);
    EXPECT_EQ(closes.load(), 1);
}

TEST_F(DmUiLifecycle, PinWorkDrainsBeforeFailureRecovery)
{
    ASSERT_EQ(InvokeDmUi(DM_UI_PIN, "123456", 6), 0);
    closeResult = DISCONNECT_ERROR;
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_PIN);
    EXPECT_EQ(InvokeDmUi(DM_UI_INPUT, "synthetic", 9), 0);
    EXPECT_EQ(residentCalls.load(), 0);
    RunWork();
    EXPECT_EQ(workCalls.load(), 0);
    EXPECT_EQ(residentCalls.load(), 1);
    EXPECT_EQ(lastResidentOperation.load(), DM_UI_INPUT);
    EXPECT_EQ(closes.load(), 0);
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_PIN);
    EXPECT_EQ(residentCalls.load(), 1);
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_INPUT);
    EXPECT_EQ(residentCalls.load(), 2);
    EXPECT_EQ(lastResidentOperation.load(), DM_UI_CLOSE);
}

TEST_F(DmUiLifecycle, MissingV2SymbolAndOldApiVersionAreRejected)
{
    failSessionSymbol = true;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), -1);
    failSessionSymbol = false;
    constexpr uint32_t OLD_SESSION_VERSION = 1;
    sessionVersion = OLD_SESSION_VERSION;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), -1);
    EXPECT_EQ(calls.load(), 0);
    EXPECT_EQ(destroys.load(), 0);
    sessionVersion = DM_UI_SESSION_API_VERSION;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, "{}", 2), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(destroys.load(), 1);
}
