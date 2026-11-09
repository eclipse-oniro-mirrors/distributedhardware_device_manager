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
#include <chrono>
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
constexpr int RELOAD_CYCLES = 5;
constexpr int TWO_SESSIONS = 2;
constexpr int THREE_SESSIONS = 3;
constexpr int SHOW_AND_CLOSE_CALLS = 2;
constexpr int REPLAY_AND_NEXT_SHOW_CALLS = 3;
constexpr char EMPTY_JSON[] = "{}";
constexpr size_t EMPTY_JSON_SIZE = sizeof(EMPTY_JSON) - 1;
constexpr char TEST_PIN[] = "123456";
constexpr size_t TEST_PIN_SIZE = sizeof(TEST_PIN) - 1;
constexpr char TEST_PAYLOAD[] = "synthetic";
constexpr size_t TEST_PAYLOAD_SIZE = sizeof(TEST_PAYLOAD) - 1;
std::atomic<int> g_opens{ 0 };
std::atomic<int> g_closes{ 0 };
std::atomic<int> g_destroys{ 0 };
std::atomic<int> g_calls{ 0 };
std::atomic<int> g_events{ 0 };
std::atomic<int> g_inside{ 0 };
bool g_failOpen = false;
bool g_failApi = false;
bool g_deferClose = false;
bool g_failResidentApi = false;
bool g_failCreate = false;
int32_t g_closeResult = 0;
int32_t g_disconnectResult = 0;
uint32_t g_sessionFlags = DM_UI_CAN_UNLOAD_DIALOG;
uint32_t g_sessionVersion = DM_UI_SESSION_API_VERSION;
bool g_failSessionSymbol = false;
std::atomic<int> g_workCalls{ 0 };
std::atomic<int> g_residentCalls{ 0 };
std::atomic<uint32_t> g_lastResidentOperation{ DM_UI_CONFIRM };
std::atomic<bool> g_closeOnResidentShow{ false };
std::mutex g_taskMutex;
std::vector<ffrt_function_header_t *> g_timers;
std::vector<ffrt_function_header_t *> g_workQueue;
std::set<Context *> g_contexts;
std::mutex g_gate;
std::condition_variable g_changed;
bool g_blockShow = false;
bool g_blockCallback = false;
std::atomic<uint32_t> g_lastOperation{ DM_UI_CLOSE };
bool g_entered = false;
bool g_proceed = false;
bool g_blockWork = false;
bool g_workEntered = false;
bool g_workProceed = false;
std::vector<sptr<AAFwk::IAbilityConnection>> g_connections;

void *Create(const DmUiSessionHost *host, void *connection)
{
    if (host == nullptr || connection == nullptr) {
        ADD_FAILURE() << "Missing module creation arguments";
        return nullptr;
    }
    EXPECT_EQ(host->size, sizeof(DmUiSessionHost));
    EXPECT_NE(host->submit, nullptr);
    g_connections.emplace_back(static_cast<AAFwk::IAbilityConnection *>(connection));
    if (g_failCreate) {
        return nullptr;
    }
    auto context = new Context{ *host, g_connections.back() };
    g_contexts.insert(context);
    return context;
}
void RunConnectionWork(void *)
{
    ++g_inside;
    ++g_workCalls;
    {
        std::unique_lock<std::mutex> lock(g_gate);
        if (g_blockWork) {
            g_workEntered = true;
            g_changed.notify_all();
            g_changed.wait(lock, [] { return g_workProceed; });
        }
    }
    --g_inside;
}

int32_t Invoke(void *value, uint32_t operation, const char *, size_t)
{
    if (value == nullptr) {
        ADD_FAILURE() << "Missing session context";
        return -1;
    }
    ++g_inside;
    ++g_calls;
    if (operation == DM_UI_CONFIRM) {
        std::unique_lock<std::mutex> lock(g_gate);
        if (g_blockShow) {
            g_entered = true;
            g_changed.notify_all();
            g_changed.wait(lock, [] { return g_proceed; });
        }
    }
    if (operation != DM_UI_CLOSE) {
        g_lastOperation = operation;
    }
    if (operation == DM_UI_PIN) {
        auto context = static_cast<Context *>(value);
        if (context->host.submit == nullptr) {
            ADD_FAILURE() << "Missing task dispatcher";
            --g_inside;
            return -1;
        }
        EXPECT_EQ(context->host.submit(context->host.generation, RunConnectionWork, value), 0);
    }
    if (operation == DM_UI_CLOSE && !g_deferClose && g_closeResult == 0) {
        auto context = static_cast<Context *>(value);
        if (context->connection == nullptr) {
            ADD_FAILURE() << "Missing callback bridge";
            --g_inside;
            return -1;
        }
        context->connection->OnAbilityDisconnectDone(AppExecFwk::ElementName(), g_disconnectResult);
    }
    --g_inside;
    return operation == DM_UI_CLOSE ? g_closeResult : 0;
}
void Connected(void *, void *, int32_t)
{
    ++g_events;
    ++g_inside;
    {
        std::unique_lock<std::mutex> lock(g_gate);
        if (g_blockCallback) {
            g_entered = true;
            g_changed.notify_all();
            g_changed.wait(lock, [] { return g_proceed; });
        }
    }
    --g_inside;
}
void Disconnected(void *value, int32_t result)
{
    ++g_events;
    auto context = static_cast<Context *>(value);
    ASSERT_NE(context, nullptr);
    ASSERT_NE(context->host.retire, nullptr);
    if (result == 0 || result == DM_UI_TARGET_TERMINATED) {
        context->host.retire(context->host.generation);
    }
}
void Destroy(void *context)
{
    EXPECT_EQ(g_inside.load(), 0);
    ++g_destroys;
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(g_contexts.erase(static_cast<Context *>(context)), 1U);
    delete static_cast<Context *>(context);
}
DmUiSessionApi g_api{ DM_UI_SESSION_API_VERSION,
    sizeof(DmUiSessionApi),
    DM_UI_CAN_UNLOAD_DIALOG,
    Create,
    Invoke,
    Connected,
    Disconnected,
    Destroy };
const DmUiSessionApi *GetApi()
{
    g_api.flags = g_sessionFlags;
    g_api.version = g_sessionVersion;
    return g_failApi ? nullptr : &g_api;
}
int32_t ResidentInvoke(uint32_t operation, const char *, size_t)
{
    EXPECT_EQ(g_inside.load(), 0);
    ++g_residentCalls;
    g_lastResidentOperation.store(operation);
    if (operation == DM_UI_CONFIRM && g_closeOnResidentShow.exchange(false)) {
        EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    }
    return 0;
}
const DmUiApi g_residentApi{ DM_UI_API_VERSION, sizeof(DmUiApi), ResidentInvoke };
const DmUiApi *GetResidentApi()
{
    return g_failResidentApi ? nullptr : &g_residentApi;
}
void RunTasks(std::vector<ffrt_function_header_t *> &queue, bool execute)
{
    std::vector<ffrt_function_header_t *> tasks;
    {
        std::lock_guard<std::mutex> lock(g_taskMutex);
        tasks.swap(queue);
    }
    for (auto task : tasks) {
        ASSERT_NE(task, nullptr);
        ASSERT_NE(task->exec, nullptr);
        ASSERT_NE(task->destroy, nullptr);
        if (execute) {
            task->exec(task);
        }
        task->destroy(task);
        std::free(task);
    }
}
void RunTimers(bool execute = true)
{
    RunTasks(g_timers, execute);
}
void RunWork()
{
    RunTasks(g_workQueue, true);
}
class DmUiLifecycle : public testing::Test {
public:
    void SetUp() override
    {
        ASSERT_TRUE(ResetUiStateForTest());
        g_opens = g_closes = g_destroys = g_calls = g_events = g_inside = g_residentCalls = 0;
        g_failOpen = g_failApi = g_failResidentApi = g_failCreate = g_deferClose = false;
        g_closeResult = g_disconnectResult = 0;
        g_closeOnResidentShow = false;
        g_sessionFlags = DM_UI_CAN_UNLOAD_DIALOG;
        g_sessionVersion = DM_UI_SESSION_API_VERSION;
        g_failSessionSymbol = false;
        g_workCalls = 0;
        g_blockWork = g_workEntered = g_workProceed = false;
        g_blockShow = g_blockCallback = g_entered = g_proceed = false;
        g_lastOperation = DM_UI_CLOSE;
    }
    void TearDown() override
    {
        RunWork();
        RunTimers(false);
        EXPECT_TRUE(ResetUiStateForTest());
        g_connections.clear();
        // The fixture, not the production recovery path, reclaims retained mock sessions.
        for (auto context : g_contexts) {
            if (context != nullptr) {
                delete context;
            }
        }
        g_contexts.clear();
    }
};
}
extern "C" void *WrapFfrtAllocAutoManagedFunctionStorageBase(ffrt_function_kind_t)
{
    return std::calloc(1, ffrt_auto_managed_function_storage_size);
}
extern "C" void WrapFfrtSubmitBase(
    ffrt_function_header_t *task, const ffrt_deps_t *, const ffrt_deps_t *, const ffrt_task_attr_t *attr)
{
    ASSERT_NE(task, nullptr);
    ASSERT_NE(attr, nullptr);
    auto delay = ffrt_task_attr_get_delay(attr);
    EXPECT_TRUE(delay == 0 || delay == CLOSE_TIMEOUT_US);
    std::lock_guard<std::mutex> lock(g_taskMutex);
    (delay == 0 ? g_workQueue : g_timers).push_back(task);
}
extern "C" void *WrapDlopen(const char *name, int)
{
    if (name == nullptr) {
        ADD_FAILURE() << "Missing module name";
        return nullptr;
    }
    EXPECT_STREQ(name, "libdm_ui.z.so");
    ++g_opens;
    return g_failOpen ? nullptr : &g_opens;
}
extern "C" void *WrapDlsym(void *, const char *name)
{
    if (name == nullptr) {
        ADD_FAILURE() << "Missing symbol name";
        return nullptr;
    }
    if (std::strcmp(name, "DmGetUiApiV1") == 0) {
        return reinterpret_cast<void *>(GetResidentApi);
    }
    EXPECT_STREQ(name, "DmGetUiSessionApiV2");
    return g_failSessionSymbol ? nullptr : reinterpret_cast<void *>(GetApi);
}
extern "C" void *WrapDlsymTime64(void *handle, const char *name)
{
    return WrapDlsym(handle, name);
}
extern "C" int WrapDlclose(void *)
{
    EXPECT_EQ(g_inside.load(), 0);
    ++g_closes;
    return 0;
}

namespace {
void VerifyInitializationAndReload()
{
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(g_opens.load(), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE + 1, nullptr, 0), -1);
    EXPECT_EQ(g_opens.load(), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, nullptr, 1), -1);
    g_failOpen = true;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), -1);
    g_failOpen = false;
    g_failApi = true;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), -1);
    EXPECT_EQ(g_closes.load(), 1);
    g_failApi = false;
    for (int cycle = 0; cycle < RELOAD_CYCLES; ++cycle) {
        int before = g_closes.load();
        ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
        EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
        EXPECT_EQ(g_closes.load(), before + 1);
        int callbacks = g_events.load();
        ASSERT_FALSE(g_connections.empty());
        ASSERT_NE(g_connections.back(), nullptr);
        g_connections.back()->OnAbilityConnectDone(AppExecFwk::ElementName(), nullptr, 0);
        ASSERT_FALSE(g_connections.empty());
        ASSERT_NE(g_connections.back(), nullptr);
        g_connections.back()->OnAbilityDisconnectDone(AppExecFwk::ElementName(), 0);
        EXPECT_EQ(g_events.load(), callbacks); // Old generations cannot call unloaded code.
    }
    EXPECT_EQ(g_destroys.load(), RELOAD_CYCLES);
}

void VerifyShowQueuedDuringClose()
{
    // The next show is accepted into the host queue while the old close completes.
    g_deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    ASSERT_FALSE(g_connections.empty());
    auto closingConnection = g_connections.back();
    ASSERT_NE(closingConnection, nullptr);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    int dispatched = g_calls.load();
    int before = g_closes.load();
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(g_calls.load(), dispatched);
    closingConnection->OnAbilityDisconnectDone(AppExecFwk::ElementName(), 0);
    EXPECT_EQ(g_closes.load(), before + 1);
    EXPECT_EQ(g_calls.load(), dispatched + 1);
    g_deferClose = false;
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
}

void VerifyRetirementWaitsForActiveCall()
{
    // A callback requests retirement while another module call is still running.
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    {
        std::lock_guard<std::mutex> lock(g_gate);
        g_blockCallback = true;
        g_entered = false;
        g_proceed = false;
    }
    ASSERT_FALSE(g_connections.empty());
    auto connection = g_connections.back();
    ASSERT_NE(connection, nullptr);
    std::thread active([connection] {
        connection->OnAbilityConnectDone(AppExecFwk::ElementName(), nullptr, 0);
    });
    {
        std::unique_lock<std::mutex> lock(g_gate);
        g_changed.wait(lock, [] { return g_entered; });
    }
    int before = g_closes.load();
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(g_closes.load(), before);
    {
        std::lock_guard<std::mutex> lock(g_gate);
        g_proceed = true;
        g_blockCallback = false;
        g_changed.notify_all();
    }
    active.join();
    EXPECT_EQ(g_closes.load(), before + 1);
}

void VerifyClientReleaseAndPinWork()
{
    // A UI client registered for cancellation still releases native resources.
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    int before = g_closes.load();
    DmDialogClient::GetInstance().ReleaseConfirmSession();
    EXPECT_EQ(g_closes.load(), before + 1);

    // PIN work is owned by the host and releases the module after closing.
    EXPECT_EQ(InvokeDmUi(DM_UI_PIN, TEST_PIN, TEST_PIN_SIZE), 0);
    RunWork();
    before = g_closes.load();
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(g_closes.load(), before + 1);
    DmDialogClient::GetInstance().ReleaseConfirmSession();
    EXPECT_EQ(g_closes.load(), before + 1);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE + 1, EMPTY_JSON, EMPTY_JSON_SIZE), -1);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(g_closes.load(), before + 1);
}
} // namespace

TEST_F(DmUiLifecycle, ReleaseAndReloadWithLateAndConcurrentCallbacks)
{
    ASSERT_NO_FATAL_FAILURE(VerifyInitializationAndReload());
    ASSERT_NO_FATAL_FAILURE(VerifyShowQueuedDuringClose());
    ASSERT_NO_FATAL_FAILURE(VerifyRetirementWaitsForActiveCall());
    ASSERT_NO_FATAL_FAILURE(VerifyClientReleaseAndPinWork());
}

TEST_F(DmUiLifecycle, CloseFailureUsesResidentBackendWithoutDestroyOrUnload)
{
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    g_closeResult = DISCONNECT_ERROR;
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), DISCONNECT_ERROR);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(g_residentCalls.load(), 1);
    EXPECT_EQ(g_destroys.load(), 0);
    EXPECT_EQ(g_closes.load(), 0);
    EXPECT_EQ(g_contexts.size(), 1U);
    for (size_t index = 0; index < MAX_DEFERRED_REQUESTS; ++index) {
        EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
        EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    }
    EXPECT_EQ(g_contexts.size(), 1U);
    EXPECT_EQ(g_opens.load(), 1);
}

TEST_F(DmUiLifecycle, MissingDisconnectCallbackReplaysPendingOnTimeout)
{
    g_deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(g_residentCalls.load(), 0);
    RunTimers();
    EXPECT_EQ(g_residentCalls.load(), 1);
    EXPECT_EQ(g_closes.load(), 0);
    EXPECT_EQ(g_destroys.load(), 0);
}

TEST_F(DmUiLifecycle, FailedDisconnectCallbackRecoversImmediately)
{
    g_disconnectResult = DISCONNECT_ERROR;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(g_residentCalls.load(), 1);
    EXPECT_EQ(g_closes.load(), 0);
    EXPECT_EQ(g_destroys.load(), 0);
}

TEST_F(DmUiLifecycle, StaleWatchdogCannotRecoverNewGeneration)
{
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    ASSERT_EQ(g_closes.load(), 1);
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    ASSERT_FALSE(g_connections.empty());
    auto currentConnection = g_connections.back();
    ASSERT_NE(currentConnection, nullptr);
    std::vector<ffrt_function_header_t *> staleTimers;
    {
        std::lock_guard<std::mutex> lock(g_taskMutex);
        staleTimers.swap(g_timers);
    }
    EXPECT_EQ(staleTimers.size(), 1U);
    g_deferClose = true;
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    // The stale timeout must not recover a successor that is also closing.
    RunTasks(staleTimers, true);
    currentConnection->OnAbilityDisconnectDone(AppExecFwk::ElementName(), 0);
    EXPECT_EQ(g_closes.load(), TWO_SESSIONS);
    EXPECT_EQ(g_destroys.load(), TWO_SESSIONS);
    RunTimers();
    g_deferClose = false;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(g_residentCalls.load(), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(g_closes.load(), THREE_SESSIONS);
}

TEST_F(DmUiLifecycle, RepeatedCloseCancelsDeferredDisplay)
{
    g_deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    DmDialogClient::GetInstance().ReleaseConfirmSession();
    RunTimers();
    EXPECT_EQ(g_residentCalls.load(), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(g_residentCalls.load(), 1);
}

TEST_F(DmUiLifecycle, QueueCapacityIsBoundedAndRecoveryDrainsIt)
{
    g_deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    for (size_t index = 0; index < MAX_DEFERRED_REQUESTS; ++index) {
        EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    }
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), -1);
    RunTimers();
    EXPECT_EQ(g_residentCalls.load(), static_cast<int>(MAX_DEFERRED_REQUESTS));
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
}

TEST_F(DmUiLifecycle, RecoveryWaitsForExecutingModuleCall)
{
    g_deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    {
        std::lock_guard<std::mutex> lock(g_gate);
        g_blockCallback = true;
    }
    ASSERT_FALSE(g_connections.empty());
    auto activeConnection = g_connections.back();
    ASSERT_NE(activeConnection, nullptr);
    std::thread running([activeConnection] {
        activeConnection->OnAbilityConnectDone(AppExecFwk::ElementName(), nullptr, 0);
    });
    {
        std::unique_lock<std::mutex> lock(g_gate);
        g_changed.wait(lock, [] { return g_entered; });
    }
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    RunTimers();
    EXPECT_EQ(g_residentCalls.load(), 0);
    EXPECT_EQ(g_closes.load(), 0);
    {
        std::lock_guard<std::mutex> lock(g_gate);
        g_blockCallback = false;
        g_proceed = true;
        g_changed.notify_all();
    }
    running.join();
    EXPECT_EQ(g_residentCalls.load(), 1);
    EXPECT_EQ(g_destroys.load(), 0);
}

TEST_F(DmUiLifecycle, LateCallbackCannotUnloadResidentBackend)
{
    g_deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    ASSERT_FALSE(g_connections.empty());
    auto old = g_connections.back();
    ASSERT_NE(old, nullptr);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    RunTimers();
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    old->OnAbilityDisconnectDone(AppExecFwk::ElementName(), 0);
    int before = g_events.load();
    old->OnAbilityConnectDone(AppExecFwk::ElementName(), nullptr, 0);
    EXPECT_EQ(g_events.load(), before);
    EXPECT_EQ(g_closes.load(), 0);
    EXPECT_EQ(g_destroys.load(), 0);
    DmDialogClient::GetInstance().ReleaseConfirmSession();
    EXPECT_EQ(g_lastResidentOperation.load(), DM_UI_CLOSE);
    int callsBeforeInvalid = g_residentCalls.load();
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE + 1, EMPTY_JSON, EMPTY_JSON_SIZE), -1);
    EXPECT_EQ(g_residentCalls.load(), callsBeforeInvalid);
}

TEST_F(DmUiLifecycle, RegisteredUiCloseFailureAlsoRecovers)
{
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    g_closeResult = DISCONNECT_ERROR;
    DmDialogClient::GetInstance().ReleaseConfirmSession();
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(g_residentCalls.load(), 1);
    EXPECT_EQ(g_destroys.load(), 0);
}

TEST_F(DmUiLifecycle, MissingResidentApiAndCreateFailureCanRetry)
{
    g_failResidentApi = true;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), -1);
    g_failResidentApi = false;
    g_failCreate = true;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), -1);
    g_failCreate = false;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(g_destroys.load(), 1);
}

TEST_F(DmUiLifecycle, MissingUnloadCapabilityIsRejectedAndCanRetry)
{
    g_sessionFlags = 0;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), -1);
    EXPECT_EQ(g_opens.load(), 1);
    EXPECT_EQ(g_closes.load(), 1);
    EXPECT_EQ(g_destroys.load(), 0);
    EXPECT_EQ(g_calls.load(), 0);
    EXPECT_TRUE(g_contexts.empty());
    g_sessionFlags = DM_UI_CAN_UNLOAD_DIALOG;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(g_destroys.load(), 1);
    EXPECT_EQ(g_closes.load(), TWO_SESSIONS);
    RunTimers();
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(g_opens.load(), THREE_SESSIONS);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(g_destroys.load(), TWO_SESSIONS);
    EXPECT_EQ(g_closes.load(), THREE_SESSIONS);
    EXPECT_EQ(g_residentCalls.load(), 0);
}

namespace {
void VerifySuccessfulDisconnectBeforeDrain(bool acknowledgeBeforeTimeout)
{
    g_deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    ASSERT_FALSE(g_connections.empty());
    auto connection = g_connections.back();
    ASSERT_NE(connection, nullptr);
    {
        std::lock_guard<std::mutex> lock(g_gate);
        g_blockCallback = true;
    }
    ASSERT_FALSE(g_connections.empty());
    auto activeConnection = g_connections.back();
    ASSERT_NE(activeConnection, nullptr);
    std::thread running([activeConnection] {
        activeConnection->OnAbilityConnectDone(AppExecFwk::ElementName(), nullptr, 0);
    });
    {
        std::unique_lock<std::mutex> lock(g_gate);
        g_changed.wait(lock, [] { return g_entered; });
    }
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    if (acknowledgeBeforeTimeout) {
        connection->OnAbilityDisconnectDone(AppExecFwk::ElementName(), 0);
        RunTimers();
    } else {
        RunTimers();
        connection->OnAbilityDisconnectDone(AppExecFwk::ElementName(), 0);
    }
    EXPECT_EQ(g_destroys.load(), 0);
    EXPECT_EQ(g_closes.load(), 0);
    {
        std::lock_guard<std::mutex> lock(g_gate);
        g_blockCallback = false;
        g_proceed = true;
        g_changed.notify_all();
    }
    running.join();
}

TEST_F(DmUiLifecycle, TargetTerminationReleasesWithoutExplicitClose)
{
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    ASSERT_FALSE(g_connections.empty());
    auto old = g_connections.back();
    ASSERT_NE(old, nullptr);
    old->OnAbilityDisconnectDone(AppExecFwk::ElementName(), DM_UI_TARGET_TERMINATED);
    EXPECT_EQ(g_destroys.load(), 1);
    EXPECT_EQ(g_closes.load(), 1);
    EXPECT_EQ(g_residentCalls.load(), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_INPUT, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    old->OnAbilityDisconnectDone(AppExecFwk::ElementName(), DM_UI_TARGET_TERMINATED);
    EXPECT_EQ(g_destroys.load(), 1);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(g_destroys.load(), TWO_SESSIONS);
}

} // namespace

TEST_F(DmUiLifecycle, SuccessfulDisconnectBeforeTimeoutKeepsReleasePath)
{
    ASSERT_NO_FATAL_FAILURE(VerifySuccessfulDisconnectBeforeDrain(true));
    EXPECT_EQ(g_destroys.load(), 1);
    EXPECT_EQ(g_closes.load(), 1);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(g_residentCalls.load(), 0);
    g_deferClose = false;
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(g_closes.load(), TWO_SESSIONS);
}

TEST_F(DmUiLifecycle, SuccessfulDisconnectCancelsRecoveryBeforeLastCallReturns)
{
    ASSERT_NO_FATAL_FAILURE(VerifySuccessfulDisconnectBeforeDrain(false));
    EXPECT_EQ(g_destroys.load(), 1);
    EXPECT_EQ(g_closes.load(), 1);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(g_residentCalls.load(), 0);
    g_deferClose = false;
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(g_closes.load(), TWO_SESSIONS);
}

TEST_F(DmUiLifecycle, CloseDuringReplayCancelsRemainingRequests)
{
    g_deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    constexpr size_t requestsToCancel = 3;
    for (size_t index = 0; index < requestsToCancel; ++index) {
        EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    }
    g_closeOnResidentShow = true;
    RunTimers();
    // The first show and its reentrant close run; later, stale shows are cancelled.
    EXPECT_EQ(g_residentCalls.load(), SHOW_AND_CLOSE_CALLS);
    EXPECT_EQ(g_lastResidentOperation.load(), DM_UI_CLOSE);
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(g_residentCalls.load(), REPLAY_AND_NEXT_SHOW_CALLS);
    EXPECT_EQ(g_closes.load(), 0);
}

TEST_F(DmUiLifecycle, AllDialogTypesReleaseAndReload)
{
    constexpr uint32_t operations[] = { DM_UI_CONFIRM, DM_UI_SERVICE_CONFIRM, DM_UI_PIN, DM_UI_INPUT };
    int expected = 0;
    for (uint32_t operation : operations) {
        EXPECT_EQ(InvokeDmUi(operation, TEST_PAYLOAD, TEST_PAYLOAD_SIZE), 0);
        RunWork();
        DmDialogClient::GetInstance().ReleaseSession(operation);
        EXPECT_EQ(g_closes.load(), ++expected);
        EXPECT_EQ(g_destroys.load(), expected);
    }
    EXPECT_EQ(g_workCalls.load(), 1);
}

TEST_F(DmUiLifecycle, QueuedPinWorkKeepsLeaseUntilCancelledTaskReturns)
{
    ASSERT_EQ(InvokeDmUi(DM_UI_PIN, TEST_PIN, TEST_PIN_SIZE), 0);
    EXPECT_EQ(g_workCalls.load(), 0);
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_PIN);
    EXPECT_EQ(g_destroys.load(), 0);
    EXPECT_EQ(g_closes.load(), 0);
    RunWork();
    EXPECT_EQ(g_workCalls.load(), 0);
    EXPECT_EQ(g_destroys.load(), 1);
    EXPECT_EQ(g_closes.load(), 1);
}

TEST_F(DmUiLifecycle, ExecutingPinWorkPreventsUnload)
{
    g_blockWork = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_PIN, TEST_PIN, TEST_PIN_SIZE), 0);
    std::thread running([] { RunWork(); });
    {
        std::unique_lock<std::mutex> lock(g_gate);
        g_changed.wait(lock, [] { return g_workEntered; });
    }
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_PIN);
    EXPECT_EQ(g_destroys.load(), 0);
    EXPECT_EQ(g_closes.load(), 0);
    RunTimers();
    {
        std::lock_guard<std::mutex> lock(g_gate);
        g_workProceed = true;
        g_changed.notify_all();
    }
    running.join();
    EXPECT_EQ(g_workCalls.load(), 1);
    EXPECT_EQ(g_destroys.load(), 1);
    EXPECT_EQ(g_closes.load(), 1);
    EXPECT_EQ(g_residentCalls.load(), 0);
}

TEST_F(DmUiLifecycle, DifferentDialogCancellationCannotCloseCurrentDialog)
{
    ASSERT_EQ(InvokeDmUi(DM_UI_INPUT, TEST_PAYLOAD, TEST_PAYLOAD_SIZE), 0);
    int dispatched = g_calls.load();
    DmDialogClient::GetInstance().ReleaseConfirmSession();
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_PIN);
    EXPECT_EQ(g_calls.load(), dispatched);
    EXPECT_EQ(g_closes.load(), 0);
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_INPUT);
    EXPECT_EQ(g_closes.load(), 1);
    ASSERT_EQ(InvokeDmUi(DM_UI_SERVICE_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    DmDialogClient::GetInstance().ReleaseConfirmSession();
    EXPECT_EQ(g_closes.load(), TWO_SESSIONS);
}

TEST_F(DmUiLifecycle, TypedCancelPreservesOtherQueuedDialogs)
{
    g_deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    ASSERT_FALSE(g_connections.empty());
    auto connection = g_connections.back();
    ASSERT_NE(connection, nullptr);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    int dispatched = g_calls.load();
    EXPECT_EQ(InvokeDmUi(DM_UI_INPUT, TEST_PAYLOAD, TEST_PAYLOAD_SIZE), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_SERVICE_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    DmDialogClient::GetInstance().ReleaseConfirmSession();
    connection->OnAbilityDisconnectDone(AppExecFwk::ElementName(), 0);
    EXPECT_EQ(g_calls.load(), dispatched + 1);
    DmDialogClient::GetInstance().ReleaseConfirmSession();
    EXPECT_EQ(g_calls.load(), dispatched + 1);
    g_deferClose = false;
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_INPUT);
    EXPECT_EQ(g_closes.load(), TWO_SESSIONS);
}

TEST_F(DmUiLifecycle, SupersededPinWorkDoesNotConnectAfterInput)
{
    ASSERT_EQ(InvokeDmUi(DM_UI_PIN, TEST_PIN, TEST_PIN_SIZE), 0);
    ASSERT_EQ(InvokeDmUi(DM_UI_INPUT, TEST_PAYLOAD, TEST_PAYLOAD_SIZE), 0);
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_PIN);
    RunWork();
    EXPECT_EQ(g_workCalls.load(), 0);
    EXPECT_EQ(g_closes.load(), 0);
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_INPUT);
    EXPECT_EQ(g_closes.load(), 1);
}

TEST_F(DmUiLifecycle, PinWorkDrainsBeforeFailureRecovery)
{
    ASSERT_EQ(InvokeDmUi(DM_UI_PIN, TEST_PIN, TEST_PIN_SIZE), 0);
    g_closeResult = DISCONNECT_ERROR;
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_PIN);
    EXPECT_EQ(InvokeDmUi(DM_UI_INPUT, TEST_PAYLOAD, TEST_PAYLOAD_SIZE), 0);
    EXPECT_EQ(g_residentCalls.load(), 0);
    RunWork();
    EXPECT_EQ(g_workCalls.load(), 0);
    EXPECT_EQ(g_residentCalls.load(), 1);
    EXPECT_EQ(g_lastResidentOperation.load(), DM_UI_INPUT);
    EXPECT_EQ(g_closes.load(), 0);
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_PIN);
    EXPECT_EQ(g_residentCalls.load(), 1);
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_INPUT);
    EXPECT_EQ(g_residentCalls.load(), SHOW_AND_CLOSE_CALLS);
    EXPECT_EQ(g_lastResidentOperation.load(), DM_UI_CLOSE);
}

TEST_F(DmUiLifecycle, MissingV2SymbolAndOldApiVersionAreRejected)
{
    g_failSessionSymbol = true;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), -1);
    g_failSessionSymbol = false;
    constexpr uint32_t oldSessionVersion = 1;
    g_sessionVersion = oldSessionVersion;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), -1);
    EXPECT_EQ(g_calls.load(), 0);
    EXPECT_EQ(g_destroys.load(), 0);
    g_sessionVersion = DM_UI_SESSION_API_VERSION;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(g_destroys.load(), 1);
}

// @tc.name: RepeatedGlobalClose001
// @tc.desc: Repeated closes cancel queued displays without disconnecting twice.
// @tc.type: FUNC
TEST_F(DmUiLifecycle, RepeatedGlobalClose001)
{
    g_deferClose = true;
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    ASSERT_FALSE(g_connections.empty());
    ASSERT_FALSE(g_connections.empty());
    auto connection = g_connections.back();
    ASSERT_NE(connection, nullptr);
    ASSERT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    int calls = g_calls.load();
    ASSERT_EQ(InvokeDmUi(DM_UI_INPUT, TEST_PAYLOAD, TEST_PAYLOAD_SIZE), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(g_calls.load(), calls);
    connection->OnAbilityDisconnectDone(AppExecFwk::ElementName(), 0);
    EXPECT_EQ(g_destroys.load(), 1);
    EXPECT_EQ(g_closes.load(), 1);
    EXPECT_EQ(g_calls.load(), calls);
    ASSERT_EQ(InvokeDmUi(DM_UI_INPUT, TEST_PAYLOAD, TEST_PAYLOAD_SIZE), 0);
    EXPECT_EQ(g_residentCalls.load(), 0);
    g_deferClose = false;
    DmDialogClient::GetInstance().ReleaseSession(DM_UI_INPUT);
    EXPECT_EQ(g_destroys.load(), TWO_SESSIONS);
}

// @tc.name: ConcurrentShowCancellation001
// @tc.desc: Typed cancellation follows actual serialized display order.
// @tc.type: FUNC
TEST_F(DmUiLifecycle, ConcurrentShowCancellation001)
{
    g_blockShow = true;
    std::thread first([] { EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0); });
    {
        std::unique_lock<std::mutex> lock(g_gate);
        g_changed.wait(lock, [] { return g_entered; });
    }
    std::atomic<bool> secondStarted{ false };
    std::thread second([&secondStarted] {
        secondStarted = true;
        EXPECT_EQ(InvokeDmUi(DM_UI_INPUT, TEST_PAYLOAD, TEST_PAYLOAD_SIZE), 0);
    });
    while (!secondStarted.load()) {
        std::this_thread::yield();
    }
    // Bounded wait also allows the old implementation to enter its second call.
    constexpr auto overlapWindow = std::chrono::milliseconds(50);
    std::this_thread::sleep_for(overlapWindow);
    {
        std::lock_guard<std::mutex> lock(g_gate);
        g_blockShow = false;
        g_proceed = true;
        g_changed.notify_all();
    }
    first.join();
    second.join();
    uint32_t last = g_lastOperation.load();
    ASSERT_LT(last, static_cast<uint32_t>(DM_UI_CLOSE));
    DmDialogClient::GetInstance().ReleaseSession(last);
    EXPECT_EQ(g_destroys.load(), 1);
    EXPECT_EQ(g_closes.load(), 1);
}

// @tc.name: MissingFunctionPointers001
// @tc.desc: Incomplete function tables must never be dereferenced.
// @tc.type: FUNC
TEST_F(DmUiLifecycle, MissingFunctionPointers001)
{
    const DmUiSessionApi saved = g_api;
    g_api.create = nullptr;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), -1);
    g_api = saved;
    g_api.invoke = nullptr;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), -1);
    g_api = saved;
    g_api.connected = nullptr;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), -1);
    g_api = saved;
    g_api.disconnected = nullptr;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), -1);
    g_api = saved;
    g_api.destroy = nullptr;
    EXPECT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), -1);
    g_api = saved;
    EXPECT_EQ(g_calls.load(), 0);
    EXPECT_TRUE(g_contexts.empty());
    ASSERT_EQ(InvokeDmUi(DM_UI_CONFIRM, EMPTY_JSON, EMPTY_JSON_SIZE), 0);
    EXPECT_EQ(InvokeDmUi(DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(g_destroys.load(), 1);
}
