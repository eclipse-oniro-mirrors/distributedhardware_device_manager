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
#include <thread>
#include <gtest/gtest.h>
#include "ability_connect_callback_stub.h"
#include "ability_manager_ipc_interface_code.h"
#include "dm_system_ability_manager_mock.h"
#include "dm_ui_api.h"
#include "ipc_object_stub.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"

namespace {
OHOS::sptr<OHOS::ISystemAbilityManager> g_sessionSam;
}
namespace OHOS {
sptr<ISystemAbilityManager> SystemAbilityManagerClient::GetSystemAbilityManager()
{
    return g_sessionSam;
}
} // namespace OHOS

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::DistributedHardware;
using namespace testing;
namespace {
constexpr uint64_t TEST_GENERATION = 1;
constexpr int32_t DISCONNECT_FAILURE = -2;
constexpr uint32_t SHOW_DIALOG_CODE = 1;
constexpr uint32_t CLOSE_DIALOG_CODE = 3;
constexpr char PARAMS[] = "{}";
constexpr size_t PARAMS_SIZE = sizeof(PARAMS) - 1;
std::atomic<int> g_retired{ 0 };

class Connection final : public AAFwk::AbilityConnectionStub {
public:
    void OnAbilityConnectDone(const AppExecFwk::ElementName &, const sptr<IRemoteObject> &, int) override {}
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &, int) override {}
};

class AbilityRemote final : public IPCObjectStub {
public:
    bool IsProxyObject() const override
    {
        // Select the official AbilityManagerProxy; keep its requests inside this UT.
        return true;
    }
    int SendRequest(uint32_t code, MessageParcel &, MessageParcel &reply, MessageOption &) override
    {
        int result = 0;
        if (code == static_cast<uint32_t>(AAFwk::AbilityManagerInterfaceCode::CONNECT_ABILITY_WITH_TYPE)) {
            ++connects;
        } else if (code == static_cast<uint32_t>(AAFwk::AbilityManagerInterfaceCode::DISCONNECT_ABILITY)) {
            ++disconnects;
            result = disconnectResult.load();
        } else {
            ADD_FAILURE() << "Unexpected AbilityManager request";
            return DISCONNECT_FAILURE;
        }
        return reply.WriteInt32(result) ? 0 : DISCONNECT_FAILURE;
    }
    std::atomic<int> connects{ 0 };
    std::atomic<int> disconnects{ 0 };
    std::atomic<int32_t> disconnectResult{ 0 };
};

class DialogRemote final : public IPCObjectStub {
public:
    int SendRequest(uint32_t code, MessageParcel &, MessageParcel &, MessageOption &) override
    {
        if (code == SHOW_DIALOG_CODE) {
            ++shows;
        } else if (code == CLOSE_DIALOG_CODE) {
            ++closes;
        } else {
            ADD_FAILURE() << "Unexpected dialog request";
            return DISCONNECT_FAILURE;
        }
        return 0;
    }
    std::atomic<int> shows{ 0 };
    std::atomic<int> closes{ 0 };
};

void Retire(uint64_t generation)
{
    EXPECT_EQ(generation, TEST_GENERATION);
    ++g_retired;
}
int32_t Submit(uint64_t generation, void (*work)(void *), void *context)
{
    EXPECT_EQ(generation, TEST_GENERATION);
    if (work == nullptr || context == nullptr) {
        ADD_FAILURE() << "Invalid connection work";
        return -1;
    }
    work(context);
    return 0;
}

class DmUiSession : public Test {
public:
    void SetUp() override
    {
        g_retired = 0;
        api_ = DmGetUiSessionApiV2();
        ASSERT_NE(api_, nullptr);
        ASSERT_EQ(api_->version, DM_UI_SESSION_API_VERSION);
        ASSERT_NE(api_->create, nullptr);
        ASSERT_NE(api_->invoke, nullptr);
        ASSERT_NE(api_->connected, nullptr);
        ASSERT_NE(api_->disconnected, nullptr);
        ASSERT_NE(api_->destroy, nullptr);
        sam_ = new NiceMock<SystemAbilityManagerMock>;
        ability_ = new AbilityRemote;
        dialog_ = new DialogRemote;
        connection_ = new Connection;
        ASSERT_NE(sam_, nullptr);
        ASSERT_NE(ability_, nullptr);
        ASSERT_NE(dialog_, nullptr);
        ASSERT_NE(connection_, nullptr);
        g_sessionSam = sam_;
        EXPECT_CALL(*sam_, GetSystemAbility(ABILITY_MGR_SERVICE_ID)).WillRepeatedly(Return(ability_));
        context_ = api_->create(&host_, connection_.GetRefPtr());
        ASSERT_NE(context_, nullptr);
    }
    void TearDown() override
    {
        if (api_ != nullptr && api_->destroy != nullptr && context_ != nullptr) {
            api_->destroy(context_);
            context_ = nullptr;
        }
        g_sessionSam = nullptr;
        sam_ = nullptr;
        ability_ = nullptr;
        dialog_ = nullptr;
        connection_ = nullptr;
    }
protected:
    DmUiSessionHost host_{ sizeof(DmUiSessionHost), TEST_GENERATION, Retire, Submit };
    const DmUiSessionApi *api_ = nullptr;
    void *context_ = nullptr;
    sptr<NiceMock<SystemAbilityManagerMock>> sam_;
    sptr<AbilityRemote> ability_;
    sptr<DialogRemote> dialog_;
    sptr<AAFwk::IAbilityConnection> connection_;
};

// @tc.name: NullArguments001
// @tc.desc: Private module boundaries reject null contexts and invalid host callbacks.
// @tc.type: FUNC
HWTEST_F(DmUiSession, NullArguments001, TestSize.Level1)
{
    EXPECT_EQ(api_->create(nullptr, connection_.GetRefPtr()), nullptr);
    EXPECT_EQ(api_->create(&host_, nullptr), nullptr);
    DmUiSessionHost invalid = host_;
    invalid.retire = nullptr;
    EXPECT_EQ(api_->create(&invalid, connection_.GetRefPtr()), nullptr);
    invalid = host_;
    invalid.submit = nullptr;
    EXPECT_EQ(api_->create(&invalid, connection_.GetRefPtr()), nullptr);
    EXPECT_EQ(api_->invoke(nullptr, DM_UI_CONFIRM, PARAMS, PARAMS_SIZE), -1);
    EXPECT_EQ(api_->invoke(context_, DM_UI_CONFIRM, nullptr, PARAMS_SIZE), -1);
    api_->connected(nullptr, nullptr, 0);
    api_->disconnected(nullptr, 0);
    api_->destroy(nullptr);
    EXPECT_EQ(g_retired.load(), 0);
}

// @tc.name: CloseBeforeConnect001
// @tc.desc: A close during connection waits for completion and disconnects only once.
// @tc.type: FUNC
HWTEST_F(DmUiSession, CloseBeforeConnect001, TestSize.Level1)
{
    ASSERT_EQ(api_->invoke(context_, DM_UI_CONFIRM, PARAMS, PARAMS_SIZE), 0);
    ASSERT_EQ(ability_->connects.load(), 1);
    EXPECT_EQ(api_->invoke(context_, DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(ability_->disconnects.load(), 0);
    api_->connected(context_, static_cast<IRemoteObject *>(dialog_.GetRefPtr()), 0);
    EXPECT_EQ(ability_->disconnects.load(), 1);
    EXPECT_EQ(dialog_->shows.load(), 0);
    api_->connected(context_, static_cast<IRemoteObject *>(dialog_.GetRefPtr()), 0);
    EXPECT_EQ(api_->invoke(context_, DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(ability_->disconnects.load(), 1);
    api_->disconnected(context_, 0);
    EXPECT_EQ(g_retired.load(), 1);
}

// @tc.name: RepeatedShowDuringConnect001
// @tc.desc: Pending shows reuse one connection request.
// @tc.type: FUNC
HWTEST_F(DmUiSession, RepeatedShowDuringConnect001, TestSize.Level1)
{
    ASSERT_EQ(api_->invoke(context_, DM_UI_CONFIRM, PARAMS, PARAMS_SIZE), 0);
    ASSERT_EQ(api_->invoke(context_, DM_UI_INPUT, PARAMS, PARAMS_SIZE), 0);
    EXPECT_EQ(ability_->connects.load(), 1);
    api_->connected(context_, static_cast<IRemoteObject *>(dialog_.GetRefPtr()), 0);
    EXPECT_EQ(dialog_->shows.load(), 1);
    EXPECT_EQ(api_->invoke(context_, DM_UI_CLOSE, nullptr, 0), 0);
    EXPECT_EQ(ability_->disconnects.load(), 1);
    api_->disconnected(context_, 0);
    EXPECT_EQ(g_retired.load(), 1);
}

// @tc.name: ConcurrentClose001
// @tc.desc: Concurrent module closes cannot issue two disconnect requests.
// @tc.type: FUNC
HWTEST_F(DmUiSession, ConcurrentClose001, TestSize.Level1)
{
    ASSERT_EQ(api_->invoke(context_, DM_UI_CONFIRM, PARAMS, PARAMS_SIZE), 0);
    api_->connected(context_, static_cast<IRemoteObject *>(dialog_.GetRefPtr()), 0);
    std::thread first([this] { EXPECT_EQ(api_->invoke(context_, DM_UI_CLOSE, nullptr, 0), 0); });
    std::thread second([this] { EXPECT_EQ(api_->invoke(context_, DM_UI_CLOSE, nullptr, 0), 0); });
    first.join();
    second.join();
    EXPECT_EQ(ability_->disconnects.load(), 1);
    api_->disconnected(context_, 0);
    EXPECT_EQ(g_retired.load(), 1);
}

// @tc.name: DisconnectFailureCanRetry001
// @tc.desc: A failed disconnect must not be treated as successful retirement.
// @tc.type: FUNC
HWTEST_F(DmUiSession, DisconnectFailureCanRetry001, TestSize.Level1)
{
    ASSERT_EQ(api_->invoke(context_, DM_UI_CONFIRM, PARAMS, PARAMS_SIZE), 0);
    api_->connected(context_, static_cast<IRemoteObject *>(dialog_.GetRefPtr()), 0);
    ability_->disconnectResult = DISCONNECT_FAILURE;
    EXPECT_EQ(api_->invoke(context_, DM_UI_CLOSE, nullptr, 0), DISCONNECT_FAILURE);
    EXPECT_EQ(g_retired.load(), 0);
    ability_->disconnectResult = 0;
    EXPECT_EQ(api_->invoke(context_, DM_UI_CLOSE, nullptr, 0), 0);
    constexpr int expectedAttempts = 2;
    EXPECT_EQ(ability_->disconnects.load(), expectedAttempts);
    api_->disconnected(context_, 0);
    EXPECT_EQ(g_retired.load(), 1);
}

// @tc.name: RetiredSessionCannotReconnect001
// @tc.desc: A disconnect completion is terminal even before host destruction.
// @tc.type: FUNC
HWTEST_F(DmUiSession, RetiredSessionCannotReconnect001, TestSize.Level1)
{
    ASSERT_EQ(api_->invoke(context_, DM_UI_CONFIRM, PARAMS, PARAMS_SIZE), 0);
    api_->connected(context_, static_cast<IRemoteObject *>(dialog_.GetRefPtr()), 0);
    api_->disconnected(context_, DM_UI_TARGET_TERMINATED);
    ASSERT_EQ(g_retired.load(), 1);
    EXPECT_EQ(api_->invoke(context_, DM_UI_INPUT, PARAMS, PARAMS_SIZE), 0);
    EXPECT_EQ(ability_->connects.load(), 1);
    EXPECT_EQ(dialog_->shows.load(), 1);
}

// @tc.name: AllFourDialogs001
// @tc.desc: Each real module display uses one connection and retires after closure.
// @tc.type: FUNC
HWTEST_F(DmUiSession, AllFourDialogs001, TestSize.Level1)
{
    constexpr uint32_t operations[] = { DM_UI_CONFIRM, DM_UI_SERVICE_CONFIRM, DM_UI_PIN, DM_UI_INPUT };
    int expected = 0;
    for (uint32_t operation : operations) {
        ASSERT_NE(context_, nullptr);
        ASSERT_EQ(api_->invoke(context_, operation, PARAMS, PARAMS_SIZE), 0);
        api_->connected(context_, static_cast<IRemoteObject *>(dialog_.GetRefPtr()), 0);
        EXPECT_EQ(api_->invoke(context_, DM_UI_CLOSE, nullptr, 0), 0);
        api_->disconnected(context_, 0);
        EXPECT_EQ(g_retired.load(), ++expected);
        EXPECT_EQ(ability_->connects.load(), expected);
        EXPECT_EQ(ability_->disconnects.load(), expected);
        api_->destroy(context_);
        context_ = api_->create(&host_, connection_.GetRefPtr());
        ASSERT_NE(context_, nullptr);
    }
}
} // namespace
