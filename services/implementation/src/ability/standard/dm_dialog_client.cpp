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

#include "dm_dialog_client.h"

#include <algorithm>
#include <array>
#include <condition_variable>
#include <deque>
#include <dlfcn.h>
#include <mutex>
#include "ability_connect_callback_stub.h"
#include "dm_log.h"
#include "dm_ui_api.h"
#include "ffrt.h"

namespace OHOS::DistributedHardware {
namespace {
constexpr size_t MAX_PENDING_UI_REQUESTS = 16;
constexpr uint64_t UI_CLOSE_TIMEOUT_US = 5000000;
struct UiRequest {
    uint32_t operation;
    std::string data;
    uint64_t cancelEpoch;
};
struct UiState {
    std::mutex mutex;
    std::condition_variable changed;
    void *handle = nullptr;
    const DmUiSessionApi *api = nullptr;
    const DmUiApi *residentApi = nullptr;
    void *context = nullptr;
    sptr<AAFwk::IAbilityConnection> connection;
    uint64_t generation = 0;
    size_t active = 0;
    bool transitioning = false;
    bool closing = false;
    bool retired = false;
    bool recoveryRequested = false;
    // Retain both the uncertain session and its module until process exit.
    bool residentMode = false;
    std::array<uint64_t, DM_UI_CLOSE> cancelEpoch {};
    uint32_t currentOperation = DM_UI_CLOSE;
    std::deque<UiRequest> pending;
};
UiState &State()
{
    // The callback bridge outlives IPC references; only module contexts are transient.
    static auto state = new UiState;
    return *state;
}
void ReleaseCall();
void TryFinishSession();
int32_t InvokeUiRequest(uint32_t operation, const char *data, size_t size, bool deferred, uint64_t cancelEpoch);
void DeliverConnection(uint64_t generation, IRemoteObject *remote, int32_t result, bool connected);

class UiCallGuard final {
public:
    UiCallGuard() = default;
    ~UiCallGuard()
    {
        ReleaseCall();
    }
    UiCallGuard(const UiCallGuard &) = delete;
    UiCallGuard &operator=(const UiCallGuard &) = delete;
};

uint32_t CancelGroup(uint32_t operation)
{
    return operation == DM_UI_SERVICE_CONFIRM ? DM_UI_CONFIRM : operation;
}

void CancelPending(UiState &state, uint32_t operation)
{
    if (operation == DM_UI_CLOSE) {
        for (auto &epoch : state.cancelEpoch) {
            ++epoch;
        }
        state.pending.clear();
        return;
    }
    uint32_t group = CancelGroup(operation);
    ++state.cancelEpoch[group];
    state.pending.erase(std::remove_if(state.pending.begin(), state.pending.end(),
        [group](const UiRequest &request) { return CancelGroup(request.operation) == group; }), state.pending.end());
}

int32_t SubmitSessionWork(uint64_t generation, void (*work)(void *), void *context)
{
    auto &state = State();
    uint64_t epoch;
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        if (work == nullptr || context == nullptr || context != state.context || generation != state.generation ||
            state.transitioning || state.closing || state.retired || state.residentMode ||
            state.currentOperation != DM_UI_PIN) {
            return -1;
        }
        epoch = state.cancelEpoch[DM_UI_PIN];
        ++state.active;
    }
    // Both the task body and its destructor stay in the resident host. A module
    // function pointer is called only while this queued/running lease is held.
    ffrt::submit([generation, epoch, work, context]() {
        UiCallGuard call;
        auto &state = State();
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            if (generation != state.generation || context != state.context || state.closing || state.retired ||
                state.residentMode || state.currentOperation != DM_UI_PIN || epoch != state.cancelEpoch[DM_UI_PIN]) {
                return;
            }
        }
        work(context);
    }, ffrt::task_attr().name("DmUiSessionWork"));
    return 0;
}

void RequestRecovery(uint64_t generation)
{
    auto &state = State();
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        if (state.residentMode || state.context == nullptr || !state.closing || state.retired ||
            generation != state.generation) {
            return;
        }
        state.recoveryRequested = true;
    }
    TryFinishSession();
}

void WatchClose(uint64_t generation)
{
    // A managed session has only one close cycle. Its successor has a new generation.
    // The task belongs to the resident host and captures no module-owned address.
    ffrt::submit([generation]() { RequestRecovery(generation); },
        ffrt::task_attr().name("DmUiCloseWatchdog").delay(UI_CLOSE_TIMEOUT_US));
}

class UiConnection final : public AAFwk::AbilityConnectionStub {
public:
    explicit UiConnection(uint64_t generation) : generation_(generation) {}
    void OnAbilityConnectDone(const AppExecFwk::ElementName &, const sptr<IRemoteObject> &remote,
        int result) override
    {
        DeliverConnection(generation_, remote.GetRefPtr(), result, true);
    }
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &, int result) override
    {
        DeliverConnection(generation_, nullptr, result, false);
    }
private:
    uint64_t generation_;
};

void RequestRetirement(uint64_t generation)
{
    auto &state = State();
    std::lock_guard<std::mutex> lock(state.mutex);
    if (state.context != nullptr && state.generation == generation) {
        state.retired = true;
        state.recoveryRequested = false;
    }
}

bool ValidApi(const DmUiSessionApi *api)
{
    return api != nullptr && api->version == DM_UI_SESSION_API_VERSION && api->size == sizeof(DmUiSessionApi) &&
        (api->flags & DM_UI_CAN_UNLOAD_DIALOG) != 0 &&
        api->create != nullptr && api->invoke != nullptr && api->connected != nullptr &&
        api->disconnected != nullptr && api->destroy != nullptr;
}

bool ValidResidentApi(const DmUiApi *api)
{
    return api != nullptr && api->version == DM_UI_API_VERSION && api->size == sizeof(DmUiApi) &&
        api->invoke != nullptr;
}

// Called with the host lock held; dlopen, module creation and destruction execute without it.
bool EnsureContext(std::unique_lock<std::mutex> &lock)
{
    auto &state = State();
    state.changed.wait(lock, [&state] { return !state.transitioning; });
    if (state.context != nullptr) {
        return true;
    }
    state.transitioning = true;
    void *handle = state.handle;
    const DmUiSessionApi *api = state.api;
    const DmUiApi *residentApi = state.residentApi;
    uint64_t generation = ++state.generation;
    lock.unlock();
    if (handle == nullptr) {
        handle = dlopen("libdm_ui.z.so", RTLD_NOW | RTLD_LOCAL);
        if (handle != nullptr) {
            auto getter = reinterpret_cast<DmGetUiSessionApi>(dlsym(handle, "DmGetUiSessionApiV2"));
            api = getter == nullptr ? nullptr : getter();
            auto residentGetter = reinterpret_cast<DmGetUiApi>(dlsym(handle, "DmGetUiApiV1"));
            residentApi = residentGetter == nullptr ? nullptr : residentGetter();
        }
    }
    sptr<AAFwk::IAbilityConnection> connection;
    void *context = nullptr;
    if (ValidApi(api) && ValidResidentApi(residentApi)) {
        connection = sptr<AAFwk::IAbilityConnection>(new (std::nothrow) UiConnection(generation));
        if (connection != nullptr) {
            DmUiSessionHost host { sizeof(DmUiSessionHost), generation, RequestRetirement, SubmitSessionWork };
            context = api->create(&host, connection.GetRefPtr());
        }
    }
    if (context == nullptr) {
        const char *error = dlerror();
        LOGE("UI session initialization failed: %{public}s", error == nullptr ? "invalid API or allocation" : error);
        if (handle != nullptr && state.handle == nullptr) {
            dlclose(handle);
            handle = nullptr;
            api = nullptr;
            residentApi = nullptr;
        }
    }
    lock.lock();
    state.handle = handle;
    state.api = api;
    state.residentApi = residentApi;
    state.context = context;
    state.connection = connection;
    state.transitioning = false;
    state.retired = false;
    state.closing = false;
    state.recoveryRequested = false;
    state.changed.notify_all();
    return context != nullptr;
}

void ReleaseCall()
{
    auto &state = State();
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        --state.active;
    }
    TryFinishSession();
}

void TryFinishSession()
{
    auto &state = State();
    std::unique_lock<std::mutex> lock(state.mutex);
    if (state.active != 0 || state.transitioning || state.residentMode) {
        return;
    }
    if (state.recoveryRequested) {
        // Keep exactly one uncertain session alive. All subsequent UI operations use
        // the original resident backend; no new managed sessions can accumulate.
        state.residentMode = true;
        state.recoveryRequested = false;
        LOGW("UI disconnect incomplete; switching to resident backend");
    } else if (!state.retired) {
        return;
    } else {
        state.transitioning = true;
        auto api = state.api;
        void *context = state.context;
        void *handle = state.handle;
        state.context = nullptr;
        state.connection = nullptr;
        state.handle = nullptr;
        state.api = nullptr;
        state.residentApi = nullptr;
        lock.unlock();
        api->destroy(context);
        if (handle != nullptr) {
            int result = dlclose(handle);
            LOGI("UI session module released: %{public}d", result);
        }
        lock.lock();
        state.transitioning = false;
    }
    state.retired = false;
    state.closing = false;
    state.currentOperation = DM_UI_CLOSE;
    std::deque<UiRequest> requests;
    requests.swap(state.pending);
    state.changed.notify_all();
    lock.unlock();
    for (const auto &request : requests) {
        int32_t result =
            InvokeUiRequest(request.operation, request.data.data(), request.data.size(), true, request.cancelEpoch);
        if (result != 0) {
            LOGE("Deferred UI operation %{public}u failed: %{public}d", request.operation, result);
        }
    }
}

void DeliverConnection(uint64_t generation, IRemoteObject *remote, int32_t result, bool connected)
{
    auto &state = State();
    std::unique_lock<std::mutex> lock(state.mutex);
    if (state.transitioning || state.context == nullptr || generation != state.generation || state.retired) {
        return;
    }
    ++state.active;
    auto api = state.api;
    void *context = state.context;
    lock.unlock();
    UiCallGuard call;
    if (connected) {
        api->connected(context, remote, result);
    } else {
        api->disconnected(context, result);
        if (result != 0) {
            RequestRecovery(generation);
        }
    }
    // Both the module callback and any module-owned temporaries have returned.
}
int32_t InvokeUiRequest(uint32_t operation, const char *data, size_t size, bool deferred, uint64_t cancelEpoch)
{
    if (operation > DM_UI_CLOSE || (data == nullptr && size != 0)) {
        return -1;
    }
    auto &state = State();
    std::unique_lock<std::mutex> lock(state.mutex);
    state.changed.wait(lock, [&state] { return !state.transitioning; });
    if (deferred && (operation >= DM_UI_CLOSE || cancelEpoch != state.cancelEpoch[CancelGroup(operation)])) {
        return 0;
    }
    if (operation == DM_UI_CLOSE) {
        CancelPending(state, DM_UI_CLOSE);
    }
    if (state.residentMode) {
        if (operation < DM_UI_CLOSE) {
            state.currentOperation = operation;
        }
        ++state.active;
        auto api = state.residentApi;
        lock.unlock();
        UiCallGuard call;
        return api->invoke(operation, data, size);
    }
    if (operation == DM_UI_CLOSE && state.context == nullptr) {
        return 0;
    }
    if ((state.closing || state.retired) && operation != DM_UI_CLOSE) {
        if (state.pending.size() >= MAX_PENDING_UI_REQUESTS) {
            LOGE("UI close is pending; deferred request capacity reached");
            return -1;
        }
        state.pending.push_back({ operation, std::string(data == nullptr ? "" : data, size),
            state.cancelEpoch[CancelGroup(operation)] });
        return 0;
    }
    if (!EnsureContext(lock)) {
        return -1;
    }
    if (operation < DM_UI_CLOSE) {
        state.currentOperation = operation;
    }
    bool watch = operation == DM_UI_CLOSE && !state.closing;
    if (operation == DM_UI_CLOSE) {
        state.closing = true;
    }
    ++state.active;
    auto api = state.api;
    void *context = state.context;
    uint64_t generation = state.generation;
    lock.unlock();
    UiCallGuard call;
    if (watch) {
        WatchClose(generation);
    }
    int32_t result = api->invoke(context, operation, data, size);
    if (operation == DM_UI_CLOSE && result != 0) {
        RequestRecovery(generation);
    }
    return result;
}
} // namespace

int32_t InvokeDmUi(uint32_t operation, const char *data, size_t size)
{
    return InvokeUiRequest(operation, data, size, false, 0);
}

DM_IMPLEMENT_SINGLE_INSTANCE(DmDialogClient);

void DmDialogClient::ReleaseConfirmSession()
{
    ReleaseSession(DM_UI_CONFIRM);
}

void DmDialogClient::ReleaseSession(uint32_t operation)
{
    if (operation >= DM_UI_CLOSE) {
        return;
    }
    auto &state = State();
    std::unique_lock<std::mutex> lock(state.mutex);
    state.changed.wait(lock, [&state] { return !state.transitioning; });
    CancelPending(state, operation);
    if (state.currentOperation >= DM_UI_CLOSE || CancelGroup(state.currentOperation) != CancelGroup(operation)) {
        return;
    }
    if (state.residentMode) {
        ++state.active;
        auto api = state.residentApi;
        state.currentOperation = DM_UI_CLOSE;
        lock.unlock();
        UiCallGuard call;
        if (api->invoke(DM_UI_CLOSE, nullptr, 0) != 0) {
            LOGE("Resident UI close dispatch failed");
        }
        return;
    }
    if (state.context == nullptr || state.closing || state.retired) {
        return;
    }
    state.closing = true;
    ++state.active;
    auto api = state.api;
    void *context = state.context;
    uint64_t generation = state.generation;
    lock.unlock();
    UiCallGuard call;
    WatchClose(generation);
    int32_t result = api->invoke(context, DM_UI_CLOSE, nullptr, 0);
    if (result != 0) {
        LOGE("UI session release dispatch failed: %{public}d", result);
        RequestRecovery(generation);
    }
}

#ifdef DM_UI_LIFECYCLE_TEST
// Only the UT target defines this macro; no reset entry is emitted in product builds.
bool ResetUiStateForTest()
{
    auto &state = State();
    std::lock_guard<std::mutex> lock(state.mutex);
    if (state.active != 0 || state.transitioning) {
        return false;
    }
    state.handle = nullptr;
    state.api = nullptr;
    state.residentApi = nullptr;
    state.context = nullptr;
    state.connection = nullptr;
    ++state.generation;
    CancelPending(state, DM_UI_CLOSE);
    state.currentOperation = DM_UI_CLOSE;
    state.closing = false;
    state.retired = false;
    state.recoveryRequested = false;
    state.residentMode = false;
    state.pending.clear();
    return true;
}
#endif

void DmDialogClient::ShowConfirmDialog(const std::string param)
{
    if (InvokeDmUi(DM_UI_CONFIRM, param.data(), param.size()) != 0) {
        LOGE("Confirm dialog dispatch failed");
    }
}
void DmDialogClient::ShowServiceBindConfirmDialog(const std::string param)
{
    if (InvokeDmUi(DM_UI_SERVICE_CONFIRM, param.data(), param.size()) != 0) {
        LOGE("Service confirm dialog dispatch failed");
    }
}
void DmDialogClient::ShowPinDialog(const std::string param)
{
    if (InvokeDmUi(DM_UI_PIN, param.data(), param.size()) != 0) {
        LOGE("PIN dialog dispatch failed");
    }
}
void DmDialogClient::ShowInputDialog(const std::string param)
{
    if (InvokeDmUi(DM_UI_INPUT, param.data(), param.size()) != 0) {
        LOGE("Input dialog dispatch failed");
    }
}
void DmDialogClient::CloseDialog()
{
    if (InvokeDmUi(DM_UI_CLOSE, nullptr, 0) != 0) {
        LOGE("Close dialog dispatch failed");
    }
}
} // namespace OHOS::DistributedHardware
