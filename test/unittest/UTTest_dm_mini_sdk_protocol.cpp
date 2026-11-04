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
#include <gtest/gtest.h>
#include <cstdint>
#include <vector>
#include "bt_mini_sdk.h"
#include "ipc_object_stub.h"
#include "mini_sdk_constants.h"
#include "mini_sdk_loader.h"
#include "power_mini_sdk.h"
#include "screenlock_mini_sdk.h"
#include "system_ability_definition.h"
#include "wifi_mini_sdk.h"

namespace OHOS::DistributedHardware {
namespace {
// Keep protocol expectations independent of the adapters under test.
// Contract snapshot: BluetoothState/BTStateID (bluetooth_def.h), WifiState (wifi_msg.h),
// PowerErrors (power_errors.h) and WakeupDeviceType (power_state_machine_info.h).
// Recheck these values against the service contract when updating the mini SDK protocol.
constexpr int32_t CONNECTION_FAILED = 4900101;
constexpr int32_t POWER_SUCCESS = 0;
constexpr int32_t END_DREAM = 33;
constexpr int32_t BLUETOOTH_EVENT_ON = 1;
constexpr int32_t BLUETOOTH_EVENT_OFF = 3;
constexpr int32_t WIFI_ENABLED = 3;
constexpr int32_t WIFI_DISABLED = 1;
constexpr uint32_t BLUETOOTH_CMD_GET_STATE = 4;
constexpr uint32_t WIFI_CMD_IS_ACTIVE = 0x1013;
constexpr uint32_t POWER_CMD_IS_SCREEN_ON = 23;
constexpr uint32_t POWER_CMD_WAKEUP_DEVICE = 17;
constexpr uint32_t SCREENLOCK_CMD_IS_SCREEN_LOCKED = 0;
constexpr int32_t BLUETOOTH_STATE_TURNING_ON = 1;
constexpr int32_t BLUETOOTH_STATE_ON = 2;
constexpr int32_t BLUETOOTH_STATE_TURNING_OFF = 3;
constexpr int32_t BLUETOOTH_STATE_BLE_TURNING_ON = 4;
constexpr int32_t BLUETOOTH_STATE_BLE_ON = 5;
constexpr int32_t BLUETOOTH_STATE_BLE_TURNING_OFF = 6;
constexpr int32_t BLUETOOTH_STATE_BLE_OWNER_MODE = 7;
constexpr int32_t UNKNOWN_BLUETOOTH_STATE = 99;
constexpr int32_t INVALID_SCREEN_STATE = 2;
// Five enabled states and five disabled or invalid states are queried.
constexpr int32_t BLUETOOTH_STATE_REQUEST_COUNT = 10;
constexpr int32_t WIFI_MANAGER_FAILURE_REQUEST_COUNT = 2;
constexpr int32_t SCREENLOCK_STATE_QUERY_COUNT = 2;
constexpr int32_t SCREENLOCK_RECOVERY_QUERY_COUNT = 3;
// Synthetic service error used to verify that the adapter preserves the reply.
constexpr int32_t MOCK_POWER_ERROR = 4900102;

class ReplyStub final : public IPCObjectStub {
public:
    int32_t saId = 0;
    uint32_t command = 0;
    std::u16string descriptor;
    std::vector<int32_t> values;
    int32_t transportError = 0;
    int32_t requests = 0;

    int32_t SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        ++requests;
        EXPECT_EQ(code, command);
        EXPECT_EQ(option.GetFlags(), MessageOption::TF_SYNC);
        EXPECT_EQ(data.ReadInterfaceToken(), descriptor);
        if (saId == WIFI_DEVICE_SYS_ABILITY_ID ||
            (saId == POWER_MANAGER_SERVICE_ID && command == POWER_CMD_IS_SCREEN_ON)) {
            int32_t placeholder = -1;
            EXPECT_TRUE(data.ReadInt32(placeholder));
            EXPECT_EQ(placeholder, 0);
        }
        if (saId == POWER_MANAGER_SERVICE_ID && command == POWER_CMD_WAKEUP_DEVICE) {
            int64_t timestamp = 0;
            EXPECT_TRUE(data.ReadInt64(timestamp));
            EXPECT_GT(timestamp, 0);
            EXPECT_LE(timestamp, MiniSdk::GetTickCountMs());
            EXPECT_EQ(data.ReadInt32(), END_DREAM);
            EXPECT_EQ(data.ReadString16(), u"end_dream");
        }
        // Current IPowerMgr IDL has no apiVersion field after wakeup detail.
        EXPECT_EQ(data.GetReadableBytes(), 0U);
        for (int32_t value : values) {
            EXPECT_TRUE(reply.WriteInt32(value));
        }
        return transportError;
    }
};

sptr<ReplyStub> stub;
bool g_available = true;
int32_t g_screenlockLookups = 0;

class WifiManagerStub final : public IPCObjectStub {
public:
    int32_t transportError = 0;
    bool returnDevice = true;
    int32_t requests = 0;
    int32_t SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        ++requests;
        EXPECT_EQ(code, 0U); // DevInterfaceCode::WIFI_MGR_GET_DEVICE_SERVICE
        EXPECT_EQ(option.GetFlags(), MessageOption::TF_SYNC);
        EXPECT_EQ(data.ReadInterfaceToken(), u"ohos.wifi.IWifiDeviceMgr");
        EXPECT_EQ(data.ReadInt32(), 0); // The original SDK uses WLAN instance 0.
        EXPECT_EQ(data.GetReadableBytes(), 0U);
        if (transportError == 0 && returnDevice) {
            EXPECT_TRUE(reply.WriteRemoteObject(stub));
        }
        return transportError;
    }
};
sptr<WifiManagerStub> wifiManager;

class DmMiniSdkProtocolTest : public testing::Test {
protected:
    void SetUp() override
    {
        stub = sptr<ReplyStub>::MakeSptr();
        wifiManager = sptr<WifiManagerStub>::MakeSptr();
        g_available = true;
        g_screenlockLookups = 0;
    }
    void TearDown() override
    {
        wifiManager = nullptr;
        stub = nullptr;
    }
    void Prepare(int32_t saId, uint32_t command, const std::u16string &descriptor, const std::vector<int32_t> &values)
    {
        stub->saId = saId;
        stub->command = command;
        stub->descriptor = descriptor;
        stub->values = values;
    }
};

TEST_F(DmMiniSdkProtocolTest, PrivateConstantsMatchProtocolContract)
{
    EXPECT_EQ(MiniSdk::BT_EVENT_STATE_ON, BLUETOOTH_EVENT_ON);
    EXPECT_EQ(MiniSdk::BT_EVENT_STATE_OFF, BLUETOOTH_EVENT_OFF);
    EXPECT_EQ(MiniSdk::WIFI_STATE_ENABLED, WIFI_ENABLED);
    EXPECT_EQ(MiniSdk::WIFI_STATE_DISABLED, WIFI_DISABLED);
    EXPECT_EQ(MiniSdk::POWER_WAKEUP_END_DREAM, END_DREAM);
    EXPECT_EQ(MiniSdk::POWER_ERR_OK, POWER_SUCCESS);
    EXPECT_EQ(MiniSdk::POWER_ERR_CONNECTION_FAIL, CONNECTION_FAILED);
}

TEST_F(DmMiniSdkProtocolTest, BluetoothStatesMatchProtocolContract)
{
    Prepare(BLUETOOTH_HOST_SYS_ABILITY_ID, BLUETOOTH_CMD_GET_STATE, u"ohos.ipc.IBluetoothHost", {});
    for (int32_t state : { BLUETOOTH_STATE_TURNING_ON, BLUETOOTH_STATE_ON, BLUETOOTH_STATE_TURNING_OFF,
             BLUETOOTH_STATE_BLE_ON, BLUETOOTH_STATE_BLE_OWNER_MODE }) {
        stub->values = { 0, state };
        EXPECT_TRUE(IsBleEnabled()) << state;
    }
    for (int32_t state :
        { 0, BLUETOOTH_STATE_BLE_TURNING_ON, BLUETOOTH_STATE_BLE_TURNING_OFF, -1, UNKNOWN_BLUETOOTH_STATE }) {
        stub->values = { 0, state };
        EXPECT_FALSE(IsBleEnabled()) << state;
    }
    EXPECT_EQ(stub->requests, BLUETOOTH_STATE_REQUEST_COUNT);
}

TEST_F(DmMiniSdkProtocolTest, BluetoothRejectsFailedAndTruncatedReplies)
{
    Prepare(BLUETOOTH_HOST_SYS_ABILITY_ID, BLUETOOTH_CMD_GET_STATE, u"ohos.ipc.IBluetoothHost", {});
    for (const auto &values : std::vector<std::vector<int32_t>>{ {}, { 0 }, { -1, BLUETOOTH_STATE_ON } }) {
        stub->values = values;
        EXPECT_FALSE(IsBleEnabled());
    }
    stub->values = { 0, BLUETOOTH_STATE_ON };
    stub->transportError = -1;
    EXPECT_FALSE(IsBleEnabled());
    g_available = false;
    EXPECT_FALSE(IsBleEnabled());
}

TEST_F(DmMiniSdkProtocolTest, WifiChecksExceptionReturnValueAndPayload)
{
    Prepare(WIFI_DEVICE_SYS_ABILITY_ID, WIFI_CMD_IS_ACTIVE, u"ohos.wifi.IWifiDeviceService", { 0, 0, 1 });
    EXPECT_TRUE(IsWifiActive());
    for (const auto &values :
        std::vector<std::vector<int32_t>>{ { 0, 0, 0 }, {}, { 0 }, { 0, 0 }, { -1, 0, 1 }, { 0, -1, 1 } }) {
        stub->values = values;
        EXPECT_FALSE(IsWifiActive());
    }
    stub->values = { 0, 0, 1 };
    stub->transportError = -1;
    EXPECT_FALSE(IsWifiActive());
    g_available = false;
    EXPECT_FALSE(IsWifiActive());
}

TEST_F(DmMiniSdkProtocolTest, ScreenChecksStatusAndPayload)
{
    Prepare(POWER_MANAGER_SERVICE_ID, POWER_CMD_IS_SCREEN_ON, u"OHOS.PowerMgr.IPowerMgr", { 0, 1 });
    EXPECT_TRUE(IsScreenOn());
    for (const auto &values :
        std::vector<std::vector<int32_t>>{ { 0, 0 }, {}, { 0 }, { -1, 1 }, { 0, INVALID_SCREEN_STATE } }) {
        stub->values = values;
        EXPECT_FALSE(IsScreenOn());
    }
    stub->values = { 0, 1 };
    stub->transportError = -1;
    EXPECT_FALSE(IsScreenOn());
    g_available = false;
    EXPECT_FALSE(IsScreenOn());
}

TEST_F(DmMiniSdkProtocolTest, WifiRejectsMissingDeviceAndManagerFailure)
{
    Prepare(WIFI_DEVICE_SYS_ABILITY_ID, WIFI_CMD_IS_ACTIVE, u"ohos.wifi.IWifiDeviceService", { 0, 0, 1 });
    wifiManager->returnDevice = false;
    EXPECT_FALSE(IsWifiActive());
    wifiManager->returnDevice = true;
    wifiManager->transportError = -1;
    EXPECT_FALSE(IsWifiActive());
    EXPECT_EQ(wifiManager->requests, WIFI_MANAGER_FAILURE_REQUEST_COUNT);
    EXPECT_EQ(stub->requests, 0);
}

TEST_F(DmMiniSdkProtocolTest, WakeupMatchesCurrentIdlAndClientFailureMapping)
{
    Prepare(POWER_MANAGER_SERVICE_ID, POWER_CMD_WAKEUP_DEVICE, u"OHOS.PowerMgr.IPowerMgr", { 0, 0 });
    EXPECT_EQ(WakeupDevice(END_DREAM), 0);
    stub->values = { 0, MOCK_POWER_ERROR };
    EXPECT_EQ(WakeupDevice(END_DREAM), MOCK_POWER_ERROR);
    for (const auto &values : std::vector<std::vector<int32_t>>{ {}, { 0 }, { -1, 0 } }) {
        stub->values = values;
        EXPECT_EQ(WakeupDevice(END_DREAM), CONNECTION_FAILED);
    }
    stub->values = { 0, 0 };
    stub->transportError = -1;
    EXPECT_EQ(WakeupDevice(END_DREAM), CONNECTION_FAILED);
    g_available = false;
    EXPECT_EQ(WakeupDevice(END_DREAM), CONNECTION_FAILED);
}

TEST_F(DmMiniSdkProtocolTest, ScreenlockReturnsLockedAndUnlocked)
{
    Prepare(
        SCREENLOCK_SERVICE_ID, SCREENLOCK_CMD_IS_SCREEN_LOCKED, u"ohos.screenlock.ScreenLockManagerInterface", { 1 });
    EXPECT_TRUE(IsScreenLocked());
    stub->values = { 0 };
    EXPECT_FALSE(IsScreenLocked());
    EXPECT_EQ(g_screenlockLookups, SCREENLOCK_STATE_QUERY_COUNT);
    EXPECT_EQ(stub->requests, SCREENLOCK_STATE_QUERY_COUNT);
}

TEST_F(DmMiniSdkProtocolTest, ScreenlockRejectsEmptyReply)
{
    Prepare(SCREENLOCK_SERVICE_ID, SCREENLOCK_CMD_IS_SCREEN_LOCKED, u"ohos.screenlock.ScreenLockManagerInterface", {});
    EXPECT_FALSE(IsScreenLocked());
    EXPECT_EQ(stub->requests, 1);
}

TEST_F(DmMiniSdkProtocolTest, ScreenlockFailedRequestRecoversNextCall)
{
    Prepare(
        SCREENLOCK_SERVICE_ID, SCREENLOCK_CMD_IS_SCREEN_LOCKED, u"ohos.screenlock.ScreenLockManagerInterface", { 1 });
    stub->transportError = -1;
    EXPECT_FALSE(IsScreenLocked());
    stub->transportError = 0;
    EXPECT_TRUE(IsScreenLocked());
    EXPECT_EQ(g_screenlockLookups, SCREENLOCK_STATE_QUERY_COUNT);
    EXPECT_EQ(stub->requests, SCREENLOCK_STATE_QUERY_COUNT);
}

TEST_F(DmMiniSdkProtocolTest, ScreenlockServiceRecoveryUsesFreshRemote)
{
    Prepare(
        SCREENLOCK_SERVICE_ID, SCREENLOCK_CMD_IS_SCREEN_LOCKED, u"ohos.screenlock.ScreenLockManagerInterface", { 1 });
    g_available = false;
    EXPECT_FALSE(IsScreenLocked());
    EXPECT_EQ(stub->requests, 0);
    g_available = true;
    EXPECT_TRUE(IsScreenLocked());

    // A replacement service reports a different state; the old remote must not be reused.
    sptr<ReplyStub> previous = stub;
    stub = sptr<ReplyStub>::MakeSptr();
    Prepare(
        SCREENLOCK_SERVICE_ID, SCREENLOCK_CMD_IS_SCREEN_LOCKED, u"ohos.screenlock.ScreenLockManagerInterface", { 0 });
    EXPECT_FALSE(IsScreenLocked());
    EXPECT_EQ(previous->requests, 1);
    EXPECT_EQ(stub->requests, 1);
    EXPECT_EQ(g_screenlockLookups, SCREENLOCK_RECOVERY_QUERY_COUNT);
}

TEST_F(DmMiniSdkProtocolTest, LoaderReturnsCallerFallbackForMissingLibraryAndSymbol)
{
    EXPECT_FALSE(MiniSdk::Call("libdm_mini_sdk_missing_for_test.so", "IsScreenOn", false));
    EXPECT_EQ(MiniSdk::Call("libdm_mini_sdk_missing_for_test.so", "WakeupDevice", CONNECTION_FAILED, END_DREAM),
        CONNECTION_FAILED);
    EXPECT_FALSE(MiniSdk::Call("libc.so", "DmMissingSymbolForTest", false));
    EXPECT_FALSE(MiniSdk::Call("libdm_mini_sdk_missing_for_test.so", "IsScreenLocked", false));
}
} // namespace

namespace MiniSdk {
sptr<IRemoteObject> GetSaRemoteForTest(int32_t saId)
{
    // Screenlock must retain the official SDK's waiting lookup, unlike the other adapters.
    EXPECT_NE(saId, SCREENLOCK_SERVICE_ID);
    EXPECT_EQ(saId, stub->saId);
    if (!g_available) {
        return nullptr;
    }
    if (saId == WIFI_DEVICE_SYS_ABILITY_ID) {
        return wifiManager;
    }
    return stub;
}

sptr<IRemoteObject> GetSaRemoteWithWaitForTest(int32_t saId)
{
    EXPECT_EQ(saId, SCREENLOCK_SERVICE_ID);
    EXPECT_EQ(saId, stub->saId);
    ++g_screenlockLookups;
    if (!g_available) {
        return nullptr;
    }
    return stub;
}
} // namespace MiniSdk
} // namespace OHOS::DistributedHardware
