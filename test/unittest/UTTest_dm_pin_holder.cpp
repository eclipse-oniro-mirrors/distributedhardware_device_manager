/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "UTTest_dm_pin_holder.h"
#include "dm_device_info.h"

#include <unistd.h>
#include "accesstoken_kit.h"
#include "device_manager_notify.h"
#include "dm_constants.h"
#include "dm_log.h"
#include "ipc_authenticate_device_req.h"
#include "ipc_get_info_by_network_req.h"
#include "ipc_get_info_by_network_rsp.h"
#include "ipc_get_local_device_info_rsp.h"
#include "ipc_get_trustdevice_req.h"
#include "ipc_get_trustdevice_rsp.h"
#include "ipc_req.h"
#include "ipc_rsp.h"
#include "ipc_set_useroperation_req.h"
#include "ipc_skeleton.h"
#include "ipc_start_discovery_req.h"
#include "ipc_stop_discovery_req.h"
#include "ipc_publish_req.h"
#include "ipc_unpublish_req.h"
#include "ipc_unauthenticate_device_req.h"
#include "nativetoken_kit.h"
#include "nlohmann/json.hpp"
#include "securec.h"
#include "token_setproc.h"
#include "pin_holder.h"
#include "pinholder_session_callback.h"

namespace OHOS {
namespace DistributedHardware {
void DmPinHolderTest::SetUp()
{
    const int32_t permsNum = 2;
    const int32_t indexZero = 0;
    const int32_t indexOne = 1;
    uint64_t tokenId;
    const char *perms[permsNum];
    perms[indexZero] = "ohos.permission.ACCESS_SERVICE_DM";
    perms[indexOne] = "ohos.permission.DISTRIBUTED_DATASYNC";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permsNum,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "CollaborationFwk",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

void DmPinHolderTest::TearDown()
{
}

void DmPinHolderTest::SetUpTestCase()
{
}

void DmPinHolderTest::TearDownTestCase()
{
}

void DmPinHolderCallbackTest::OnCreateResult(int32_t result)
{
    std::cout << "OnCreateResult " << result << std::endl;
}

void DmPinHolderCallbackTest::OnDestroyResult(int32_t result)
{
    std::cout << "OnDestroyResult " << result << std::endl;
}

void DmPinHolderCallbackTest::OnPinHolderDestroy(DmPinType pinType, const std::string &payload)
{
    std::cout << "OnPinHolderDestroy" << std::endl;
    std::cout << "pinType: " << pinType << std::endl;
}

void DmPinHolderCallbackTest::OnPinHolderCreate(const std::string &deviceId, DmPinType pinType,
    const std::string &payload)
{
    std::cout << "OnPinHolderCreate" << std::endl;
    std::cout << "pinType: " << pinType << std::endl;
    std::cout << "payload: " << payload << std::endl;
}

void DmPinHolderCallbackTest::OnPinHolderEvent(DmPinHolderEvent event, int32_t result, const std::string &content)
{
    std::cout << "OnPinHolderEvent" << std::endl;
    std::cout << "result: " << result << std::endl;
    std::cout << "content: " << content << std::endl;
}

constexpr int32_t MSG_TYPE_CREATE_PIN_HOLDER = 600;
constexpr int32_t MSG_TYPE_CREATE_PIN_HOLDER_RESP = 601;
constexpr int32_t MSG_TYPE_DESTROY_PIN_HOLDER = 650;
constexpr int32_t MSG_TYPE_DESTROY_PIN_HOLDER_RESP = 651;

constexpr const char* TAG_PIN_TYPE = "PIN_TYPE";
constexpr const char* TAG_PAYLOAD = "PAYLOAD";
constexpr const char* TAG_REPLY = "REPLY";
namespace {
/**
 * @tc.name: InitDeviceManager_001
 * @tc.desc: 1. set packName not null
 *              set dmInitCallback not null
 *           2. call DeviceManagerImpl::InitDeviceManager with parameter
 *           4. check ret is DM_OK
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DmPinHolderTest, RegisterPinHolderCallback_101, testing::ext::TestSize.Level0)
{
    // 1. set packName not null
    std::string packName = "com.ohos.dmtest";
    // 2. set dmInitCallback not null
    std::shared_ptr<DmInitCallbackTest> callback = std::make_shared<DmInitCallbackTest>();
    int32_t ret = DeviceManager::GetInstance().InitDeviceManager(packName, callback);

    std::shared_ptr<DmPinHolderCallbackTest> pinHolderCallback = std::make_shared<DmPinHolderCallbackTest>();
    ret = DeviceManager::GetInstance().RegisterPinHolderCallback(packName, pinHolderCallback);
    // 3. check ret is DM_OK
    ASSERT_EQ(ret, DM_OK);
    DeviceManager::GetInstance().UnInitDeviceManager(packName);
}

HWTEST_F(DmPinHolderTest, RegisterPinHolderCallback_102, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.dmtest";
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    pinHolder->session_ = nullptr;
    int32_t ret = pinHolder->RegisterPinHolderCallback(packName);
    ASSERT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DmPinHolderTest, RegisterPinHolderCallback_103, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.dmtest";
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    pinHolder->session_ = std::make_shared<PinHolderSession>();
    int32_t ret = pinHolder->RegisterPinHolderCallback(packName);
    ASSERT_EQ(ret, DM_OK);
}

HWTEST_F(DmPinHolderTest, CreatePinholder_101, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.dmtest";
    std::shared_ptr<DmInitCallbackTest> callback = std::make_shared<DmInitCallbackTest>();
    int32_t ret = DeviceManager::GetInstance().InitDeviceManager(packName, callback);

    std::shared_ptr<DmPinHolderCallbackTest> pinHolderCallback = std::make_shared<DmPinHolderCallbackTest>();
    ret = DeviceManager::GetInstance().RegisterPinHolderCallback(packName, pinHolderCallback);
    PeerTargetId targetId;
    DmPinType pinType = NUMBER_PIN_CODE;
    std::string payload = "";
    ret = DeviceManager::GetInstance().CreatePinHolder(packName, targetId, pinType, payload);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
    DeviceManager::GetInstance().UnInitDeviceManager(packName);
}

HWTEST_F(DmPinHolderTest, CreatePinholder_102, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.dmtest";
    PeerTargetId targetId;
    DmPinType pinType = DmPinType::NUMBER_PIN_CODE;
    std::string payload;
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    pinHolder->registerPkgName_ = "";
    int32_t ret = pinHolder->CreatePinHolder(packName, targetId, pinType, payload);
    ASSERT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DmPinHolderTest, CreatePinholder_103, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.dmtest";
    PeerTargetId targetId;
    DmPinType pinType = DmPinType::NUMBER_PIN_CODE;
    std::string payload;
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    pinHolder->registerPkgName_ = "dmtest";
    int32_t ret = pinHolder->CreatePinHolder(packName, targetId, pinType, payload);
    ASSERT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DmPinHolderTest, CreatePinholder_105, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.dmtest";
    PeerTargetId targetId = {
        .deviceId = "",
        .brMac = "",
        .bleMac = "",
        .wifiIp = "",
    };

    DmPinType pinType = DmPinType::NUMBER_PIN_CODE;
    std::string payload;
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    pinHolder->registerPkgName_ = packName;
    int32_t ret = pinHolder->CreatePinHolder(packName, targetId, pinType, payload);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DmPinHolderTest, CreatePinholder_106, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.dmtest";
    PeerTargetId targetId = {
        .deviceId = "deviceId",
        .brMac = "brMac",
        .bleMac = "bleMac",
        .wifiIp = "wifiIp",
    };

    DmPinType pinType = DmPinType::NUMBER_PIN_CODE;
    std::string payload;
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    pinHolder->registerPkgName_ = packName;
    pinHolder->listener_ = nullptr;
    int32_t ret = pinHolder->CreatePinHolder(packName, targetId, pinType, payload);
    ASSERT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DmPinHolderTest, CreatePinholder_107, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.dmtest";
    PeerTargetId targetId = {
        .deviceId = "deviceId",
        .brMac = "brMac",
        .bleMac = "bleMac",
        .wifiIp = "wifiIp",
    };

    DmPinType pinType = DmPinType::NUMBER_PIN_CODE;
    std::string payload;
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    pinHolder->registerPkgName_ = packName;
    pinHolder->session_ = nullptr;
    int32_t ret = pinHolder->CreatePinHolder(packName, targetId, pinType, payload);
    ASSERT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DmPinHolderTest, CreatePinholder_108, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.dmtest";
    PeerTargetId targetId = {
        .deviceId = "deviceId",
        .brMac = "brMac",
        .bleMac = "bleMac",
        .wifiIp = "wifiIp",
    };

    DmPinType pinType = DmPinType::NUMBER_PIN_CODE;
    std::string payload;
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    pinHolder->registerPkgName_ = packName;
    pinHolder->sourceState_ = SOURCE_CREATE;
    int32_t ret = pinHolder->CreatePinHolder(packName, targetId, pinType, payload);
    ASSERT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DmPinHolderTest, DestroyPinHolder_101, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.dmtest";
    PeerTargetId targetId = {
        .deviceId = "deviceId",
        .brMac = "brMac",
        .bleMac = "bleMac",
        .wifiIp = "wifiIp",
    };
    DmPinType pinType = DmPinType::NUMBER_PIN_CODE;
    std::string payload;
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    pinHolder->listener_ = nullptr;
    int32_t ret = pinHolder->DestroyPinHolder(packName, targetId, pinType, payload);
    ASSERT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DmPinHolderTest, DestroyPinHolder_102, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.dmtest";
    PeerTargetId targetId = {
        .deviceId = "deviceId",
        .brMac = "brMac",
        .bleMac = "bleMac",
        .wifiIp = "wifiIp",
    };
    DmPinType pinType = DmPinType::NUMBER_PIN_CODE;
    std::string payload;
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    pinHolder->session_ = nullptr;
    int32_t ret = pinHolder->DestroyPinHolder(packName, targetId, pinType, payload);
    ASSERT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DmPinHolderTest, DestroyPinHolder_103, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.dmtest";
    PeerTargetId targetId = {
        .deviceId = "deviceId",
        .brMac = "brMac",
        .bleMac = "bleMac",
        .wifiIp = "wifiIp",
    };
    DmPinType pinType = DmPinType::NUMBER_PIN_CODE;
    std::string payload;
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    pinHolder->registerPkgName_ = "";
    int32_t ret = pinHolder->DestroyPinHolder(packName, targetId, pinType, payload);
    ASSERT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DmPinHolderTest, DestroyPinHolder_104, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.dmtest";
    PeerTargetId targetId = {
        .deviceId = "deviceId",
        .brMac = "brMac",
        .bleMac = "bleMac",
        .wifiIp = "wifiIp",
    };
    DmPinType pinType = DmPinType::NUMBER_PIN_CODE;
    std::string payload;
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    pinHolder->registerPkgName_ = "dmtest";
    int32_t ret = pinHolder->DestroyPinHolder(packName, targetId, pinType, payload);
    ASSERT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DmPinHolderTest, DestroyPinHolder_105, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.dmtest";
    PeerTargetId targetId = {
        .deviceId = "",
        .brMac = "",
        .bleMac = "",
        .wifiIp = "",
    };
    DmPinType pinType = DmPinType::NUMBER_PIN_CODE;
    std::string payload;
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    pinHolder->registerPkgName_ = packName;
    int32_t ret = pinHolder->DestroyPinHolder(packName, targetId, pinType, payload);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DmPinHolderTest, DestroyPinHolder_106, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.dmtest";
    PeerTargetId targetId = {
        .deviceId = "deviceId",
        .brMac = "brMac",
        .bleMac = "bleMac",
        .wifiIp = "wifiIp",
    };
    DmPinType pinType = DmPinType::NUMBER_PIN_CODE;
    std::string payload;
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    pinHolder->registerPkgName_ = packName;
    pinHolder->sessionId_ = 0;
    pinHolder->sourceState_ = SOURCE_DESTROY;
    pinHolder->listener_ = std::make_shared<IDeviceManagerServiceListenerTest>();
    int32_t ret = pinHolder->DestroyPinHolder(packName, targetId, pinType, payload);
    ASSERT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DmPinHolderTest, CreateGeneratePinHolderMsg_101, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    pinHolder->listener_ = nullptr;
    int32_t ret = pinHolder->CreateGeneratePinHolderMsg();
    ASSERT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DmPinHolderTest, CreateGeneratePinHolderMsg_102, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    pinHolder->session_ = nullptr;
    int32_t ret = pinHolder->CreateGeneratePinHolderMsg();
    ASSERT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DmPinHolderTest, ParseMsgType_101, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    std::string message;
    int32_t ret = pinHolder->ParseMsgType(message);
    ASSERT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DmPinHolderTest, ProcessCreateMsg_101, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    std::string message;
    pinHolder->listener_ = nullptr;
    pinHolder->ProcessCreateMsg(message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, ProcessCreateMsg_102, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    std::string message;
    pinHolder->session_ = nullptr;
    pinHolder->ProcessCreateMsg(message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, ProcessCreateMsg_103, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    nlohmann::json jsonObject;
    std::string message = jsonObject.dump();
    pinHolder->ProcessCreateMsg(message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, ProcessCreateMsg_104, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    nlohmann::json jsonObject;
    jsonObject[TAG_PIN_TYPE] = "TAG_PIN_TYPE";
    std::string message = jsonObject.dump();
    pinHolder->ProcessCreateMsg(message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, ProcessCreateMsg_105, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    nlohmann::json jsonObject;
    jsonObject[TAG_PIN_TYPE] = DmPinType::SUPER_SONIC;
    jsonObject[TAG_PAYLOAD] = DmPinType::SUPER_SONIC;
    std::string message = jsonObject.dump();
    pinHolder->ProcessCreateMsg(message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, ProcessCreateRespMsg_101, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    nlohmann::json jsonObject;
    std::string message = jsonObject.dump();
    pinHolder->ProcessCreateRespMsg(message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, ProcessCreateRespMsg_102, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    nlohmann::json jsonObject;
    jsonObject[TAG_REPLY] = DmPinType::NUMBER_PIN_CODE;
    std::string message = jsonObject.dump();
    pinHolder->listener_ = nullptr;
    pinHolder->ProcessCreateRespMsg(message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, ProcessCreateRespMsg_103, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    nlohmann::json jsonObject;
    jsonObject[TAG_REPLY] = DmPinType::SUPER_SONIC;
    std::string message = jsonObject.dump();
    pinHolder->session_ = nullptr;
    pinHolder->ProcessCreateRespMsg(message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, ProcessCreateRespMsg_104, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    nlohmann::json jsonObject;
    jsonObject[TAG_REPLY] = DmPinType::NUMBER_PIN_CODE;
    std::string message = jsonObject.dump();
    pinHolder->session_ = nullptr;
    pinHolder->ProcessCreateRespMsg(message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, ProcessDestroyMsg_101, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    std::string message;
    pinHolder->listener_ = nullptr;
    pinHolder->ProcessDestroyMsg(message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, ProcessDestroyMsg_102, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    std::string message;
    pinHolder->session_ = nullptr;
    pinHolder->ProcessDestroyMsg(message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, ProcessDestroyMsg_103, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    nlohmann::json jsonObject;
    std::string message = jsonObject.dump();
    pinHolder->ProcessDestroyMsg(message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, ProcessDestroyMsg_104, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    nlohmann::json jsonObject;
    jsonObject[TAG_PIN_TYPE] = "TAG_PIN_TYPE";
    std::string message = jsonObject.dump();
    pinHolder->ProcessDestroyMsg(message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, ProcessDestroyMsg_105, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    nlohmann::json jsonObject;
    jsonObject[TAG_PIN_TYPE] = DmPinType::SUPER_SONIC;
    jsonObject[TAG_PAYLOAD] = DmPinType::SUPER_SONIC;
    std::string message = jsonObject.dump();
    pinHolder->ProcessDestroyMsg(message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, CloseSession_101, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    std::string name;
    pinHolder->session_ = nullptr;
    pinHolder->CloseSession(name);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, OnDataReceived_101, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    int32_t sessionId = 1;
    nlohmann::json jsonObject;
    jsonObject[TAG_MSG_TYPE] = MSG_TYPE_CREATE_PIN_HOLDER;
    std::string message = jsonObject.dump();
    pinHolder->OnDataReceived(sessionId, message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, OnDataReceived_102, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    int32_t sessionId = 1;
    nlohmann::json jsonObject;
    jsonObject[TAG_MSG_TYPE] = MSG_TYPE_CREATE_PIN_HOLDER_RESP;
    std::string message = jsonObject.dump();
    pinHolder->OnDataReceived(sessionId, message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, OnDataReceived_103, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    int32_t sessionId = 1;
    nlohmann::json jsonObject;
    jsonObject[TAG_MSG_TYPE] = MSG_TYPE_DESTROY_PIN_HOLDER;
    std::string message = jsonObject.dump();
    pinHolder->OnDataReceived(sessionId, message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, OnDataReceived_104, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    int32_t sessionId = 1;
    nlohmann::json jsonObject;
    jsonObject[TAG_MSG_TYPE] = MSG_TYPE_DESTROY_PIN_HOLDER_RESP;
    std::string message = jsonObject.dump();
    pinHolder->OnDataReceived(sessionId, message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, OnDataReceived_105, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    int32_t sessionId = 1;
    int32_t data = 300;
    nlohmann::json jsonObject;
    jsonObject[TAG_MSG_TYPE] = data;
    std::string message = jsonObject.dump();
    pinHolder->OnDataReceived(sessionId, message);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, GetPeerDeviceId_101, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    int32_t sessionId = 1;
    std::string udidHash;
    pinHolder->GetPeerDeviceId(sessionId, udidHash);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, OnSessionOpened_101, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    int32_t sessionId = 1;
    int32_t sessionSide = 0;
    int32_t result = 0;
    pinHolder->OnSessionOpened(sessionId, sessionSide, result);
    ASSERT_NE(pinHolder->timer_, nullptr);
}

HWTEST_F(DmPinHolderTest, OnSessionOpened_102, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    int32_t sessionId = 1;
    int32_t sessionSide = 1;
    int32_t result = 1;
    pinHolder ->listener_ = nullptr;
    pinHolder->OnSessionOpened(sessionId, sessionSide, result);
    ASSERT_NE(pinHolder->timer_, nullptr);
}


HWTEST_F(DmPinHolderTest, CheckTargetIdVaild_101, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    PeerTargetId targetId = {
        .deviceId = "",
        .brMac = "",
        .bleMac = "",
        .wifiIp = "",
    };
    int32_t ret = pinHolder->CheckTargetIdVaild(targetId);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DmPinHolderTest, CheckTargetIdVaild_102, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    PeerTargetId targetId = {
        .deviceId = "deviceId",
        .brMac = "brMac",
        .bleMac = "bleMac",
        .wifiIp = "wifiIp",
    };
    int32_t ret = pinHolder->CheckTargetIdVaild(targetId);
    ASSERT_EQ(ret, DM_OK);
}

HWTEST_F(DmPinHolderTest, NotifyPinHolderEvent_101, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    std::string packName = "com.ohos.dmtest";
    std::string event = "event";
    int32_t ret = pinHolder->NotifyPinHolderEvent(packName, event);
    ASSERT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DmPinHolderTest, OpenSessionServer_101, testing::ext::TestSize.Level0)
{
    std::shared_ptr<PinHolderSession> pinHolderSession = std::make_shared<PinHolderSession>();
    PeerTargetId targetId = {
        .deviceId = "deviceId",
        .brMac = "brMac",
        .bleMac = "bleMac",
        .wifiIp = "wifiIp",
    };
    int32_t ret = pinHolderSession->OpenSessionServer(targetId);
    EXPECT_NE(ret, -1);
}

HWTEST_F(DmPinHolderTest, CloseSessionServer_101, testing::ext::TestSize.Level0)
{
    std::shared_ptr<PinHolderSession> pinHolderSession = std::make_shared<PinHolderSession>();
    int32_t sessionId = 1;
    int32_t ret = pinHolderSession->CloseSessionServer(sessionId);
    EXPECT_EQ(ret, DM_OK);
}

HWTEST_F(DmPinHolderTest, OnSessionOpened_103, testing::ext::TestSize.Level0)
{
    std::shared_ptr<IDeviceManagerServiceListener> listener = std::make_shared<IDeviceManagerServiceListenerTest>();
    std::shared_ptr<PinHolder> pinHolder = std::make_shared<PinHolder>(listener);
    std::shared_ptr<PinHolderSession> pinHolderSession = std::make_shared<PinHolderSession>();
    pinHolderSession->RegisterSessionCallback(pinHolder);
    int sessionId = 1;
    int result = 1;
    int ret = pinHolderSession->OnSessionOpened(sessionId, result);
    int closeSessionId = 2;
    pinHolderSession->OnSessionClosed(closeSessionId);
    EXPECT_EQ(ret, DM_OK);
}

HWTEST_F(DmPinHolderTest, SendData_101, testing::ext::TestSize.Level0)
{
    std::shared_ptr<PinHolderSession> pinHolderSession = std::make_shared<PinHolderSession>();
    int32_t sessionId = 6;
    std::string message = "123456";
    int32_t ret = pinHolderSession->SendData(sessionId, message);
    EXPECT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DmPinHolderTest, SendData_102, testing::ext::TestSize.Level0)
{
    std::shared_ptr<PinHolderSession> pinHolderSession = std::make_shared<PinHolderSession>();
    int32_t sessionId = 6;
    std::string message = R"(
    {
        "MSG_TYPE" : "789"
    }
    )";
    int32_t ret = pinHolderSession->SendData(sessionId, message);
    EXPECT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DmPinHolderTest, SendData_103, testing::ext::TestSize.Level0)
{
    std::shared_ptr<PinHolderSession> pinHolderSession = std::make_shared<PinHolderSession>();
    int32_t sessionId = 6;
    std::string message = R"(
    {
        "MSG_TYPE" : 100
    }
    )";
    int32_t ret = pinHolderSession->SendData(sessionId, message);
    EXPECT_EQ(ret, ERR_DM_FAILED);
}

HWTEST_F(DmPinHolderTest, GetAddrByTargetId_101, testing::ext::TestSize.Level0)
{
    std::shared_ptr<PinHolderSession> pinHolderSession = std::make_shared<PinHolderSession>();
    PeerTargetId targetId = {
        .deviceId = "deviceIdTest",
        .brMac = "brMacTest",
        .bleMac = "bleMacTest",
        .wifiIp = "wifiIpTest",
        .wifiPort = 369,
    };
    ConnectionAddr addr;
    int32_t ret = pinHolderSession->GetAddrByTargetId(targetId, addr);
    EXPECT_EQ(ret, DM_OK);
}
} // namespace
} // namespace DistributedHardware
} // namespace OHOS