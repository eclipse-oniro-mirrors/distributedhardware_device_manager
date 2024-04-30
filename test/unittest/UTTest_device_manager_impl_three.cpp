/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "UTTest_device_manager_impl.h"
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
#include "securec.h"
#include "token_setproc.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
/**
 * @tc.name: RequestCredential_001
 * @tc.desc: 1. set packName null
 *              set reqJsonStr null
 *           2. call DeviceManagerImpl::RequestCredential with parameter
 *           3. check ret is ERR_DM_INPUT_PARA_INVALID
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, RequestCredential_001, testing::ext::TestSize.Level0)
{
    std::string packName;
    std::string reqJsonStr;
    std::string returnJsonStr;
    int32_t ret = DeviceManager::GetInstance().RequestCredential(packName, reqJsonStr,
                                                                returnJsonStr);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: RequestCredential_002
 * @tc.desc: 1. set packName not null
 *              set reqJsonStr not null
 *           2. MOCK IpcClientProxy SendRequest return ERR_DM_IPC_SEND_REQUEST_FAILED
 *           3. call DeviceManagerImpl::RequestCredential with parameter
 *           4. check ret is ERR_DM_IPC_SEND_REQUEST_FAILED
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, RequestCredential_002, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::string reqJsonStr = R"(
    {
        "version":"1.0.0.1",
        "userId":"4269DC28B639681698809A67EDAD08E39F207900038F91EFF95DD042FE2874E4"
    }
    )";
    std::string returnJsonStr;
    std::shared_ptr<MockIpcClientProxy> mockInstance = std::make_shared<MockIpcClientProxy>();
    std::shared_ptr<IpcClientProxy> ipcClientProxy = DeviceManagerImpl::GetInstance().ipcClientProxy_;
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = mockInstance;
    EXPECT_CALL(*mockInstance, SendRequest(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(ERR_DM_IPC_SEND_REQUEST_FAILED));
    int32_t ret = DeviceManager::GetInstance().RequestCredential(packName, reqJsonStr,
                                                                returnJsonStr);
    ASSERT_EQ(ret, ERR_DM_IPC_SEND_REQUEST_FAILED);
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = ipcClientProxy;
}

/**
 * @tc.name: RequestCredential_003
 * @tc.desc: 1. set packName not null
 *              set reqJsonStr not null
 *           2. MOCK IpcClientProxy SendRequest return DM_OK
 *           3. call DeviceManagerImpl::RequestCredential with parameter
 *           4. check ret is DM_OK
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, RequestCredential_003, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::string reqJsonStr = R"(
    {
        "version":"1.0.0.1",
        "userId":"4269DC28B639681698809A67EDAD08E39F207900038F91EFF95DD042FE2874E4"
    }
    )";
    std::string returnJsonStr;
    std::shared_ptr<DmInitCallback> callback = std::make_shared<DmInitCallbackTest>();
    DeviceManager::GetInstance().InitDeviceManager(packName, callback);
    int32_t ret = DeviceManager::GetInstance().RequestCredential(packName, reqJsonStr,
                                                                returnJsonStr);
    ASSERT_EQ(ret, DM_OK);
    DeviceManager::GetInstance().UnInitDeviceManager(packName);
}

/**
 * @tc.name: RequestCredential_004
 * @tc.desc: 1. set packName not null
 *              set reqJsonStr not null
 *           2. MOCK IpcClientProxy SendRequest return ERR_DM_INIT_FAILED
 *           3. call DeviceManagerImpl::RequestCredential with parameter
 *           4. check ret is ERR_DM_IPC_SEND_REQUEST_FAILED
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, RequestCredential_004, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::string reqJsonStr = R"(
    {
        "version":"1.0.0.1",
        "userId":"4269DC28B639681698809A67EDAD08E39F207900038F91EFF95DD042FE2874E4"
    }
    )";
    std::string returnJsonStr;
    std::shared_ptr<MockIpcClientProxy> mockInstance = std::make_shared<MockIpcClientProxy>();
    std::shared_ptr<IpcClientProxy> ipcClientProxy = DeviceManagerImpl::GetInstance().ipcClientProxy_;
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = mockInstance;
    EXPECT_CALL(*mockInstance, SendRequest(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(ERR_DM_INIT_FAILED));
    int32_t ret = DeviceManager::GetInstance().RequestCredential(packName, reqJsonStr,
                                                                returnJsonStr);
    ASSERT_EQ(ret, ERR_DM_IPC_SEND_REQUEST_FAILED);
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = ipcClientProxy;
}

/**
 * @tc.name: ImportCredential_001
 * @tc.desc: 1. set packName null
 *              set reqJsonStr null
 *           2. call DeviceManagerImpl::ImportCredential with parameter
 *           3. check ret is ERR_DM_INPUT_PARA_INVALID
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, ImportCredential_001, testing::ext::TestSize.Level0)
{
    std::string packName;
    std::string credentialInfo;
    int32_t ret = DeviceManager::GetInstance().ImportCredential(packName, credentialInfo);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: ImportCredential_002
 * @tc.desc: 1. set packName not null
 *              set credentialInfo not null
 *           2. MOCK IpcClientProxy SendRequest return ERR_DM_IPC_SEND_REQUEST_FAILED
 *           3. call DeviceManagerImpl::ImportCredential with parameter
 *           4. check ret is ERR_DM_IPC_SEND_REQUEST_FAILED
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, ImportCredential_002, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::string credentialInfo = R"(
    {
        "processType": 1,
        "authType": 1,
        "userId": "123",
        "credentialData":
        [
            {
                "credentialType": 1,
                "credentialId": "104",
                "authCode": "10F9F0576E61730193D2052B7F771887124A68F1607EFCF7796C1491F834CD92",
                "serverPk": "",
                "pkInfoSignature": "",
                "pkInfo": "",
                "peerDeviceId": ""
            }
        ]
    }
    )";
    std::shared_ptr<MockIpcClientProxy> mockInstance = std::make_shared<MockIpcClientProxy>();
    std::shared_ptr<IpcClientProxy> ipcClientProxy = DeviceManagerImpl::GetInstance().ipcClientProxy_;
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = mockInstance;
    EXPECT_CALL(*mockInstance, SendRequest(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(ERR_DM_IPC_SEND_REQUEST_FAILED));
    int32_t ret = DeviceManager::GetInstance().ImportCredential(packName, credentialInfo);
    ASSERT_EQ(ret, ERR_DM_IPC_SEND_REQUEST_FAILED);
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = ipcClientProxy;
}

/**
 * @tc.name: ImportCredential_003
 * @tc.desc: 1. set packName not null
 *              set credentialInfo not null
 *           2. MOCK IpcClientProxy SendRequest return DM_OK
 *           3. call DeviceManagerImpl::ImportCredential with parameter
 *           4. check ret is DM_OK
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, ImportCredential_003, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::string credentialInfo = R"(
    {
        "processType": 1,
        "authType": 1,
        "userId": "123",
        "credentialData":
        [
            {
                "credentialType": 1,
                "credentialId": "104",
                "authCode": "10F9F0576E61730193D2052B7F771887124A68F1607EFCF7796C1491F834CD92",
                "serverPk": "",
                "pkInfoSignature": "",
                "pkInfo": "",
                "peerDeviceId": ""
            }
        ]
    }
    )";
    std::shared_ptr<MockIpcClientProxy> mockInstance = std::make_shared<MockIpcClientProxy>();
    std::shared_ptr<IpcClientProxy> ipcClientProxy = DeviceManagerImpl::GetInstance().ipcClientProxy_;
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = mockInstance;
    EXPECT_CALL(*mockInstance, SendRequest(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(DM_OK));
    int32_t ret = DeviceManager::GetInstance().ImportCredential(packName, credentialInfo);
    ASSERT_EQ(ret, DM_OK);
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = ipcClientProxy;
}

/**
 * @tc.name: ImportCredential_004
 * @tc.desc: 1. set packName not null
 *              set credentialInfo not null
 *           2. MOCK IpcClientProxy SendRequest return ERR_DM_INIT_FAILED
 *           3. call DeviceManagerImpl::ImportCredential with parameter
 *           4. check ret is ERR_DM_IPC_SEND_REQUEST_FAILED
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, ImportCredential_004, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::string credentialInfo = R"(
    {
        "processType": 1,
        "authType": 1,
        "userId": "123",
        "credentialData":
        [
            {
                "credentialType": 1,
                "credentialId": "104",
                "authCode": "10F9F0576E61730193D2052B7F771887124A68F1607EFCF7796C1491F834CD92",
                "serverPk": "",
                "pkInfoSignature": "",
                "pkInfo": "",
                "peerDeviceId": ""
            }
        ]
    }
    )";
    std::shared_ptr<MockIpcClientProxy> mockInstance = std::make_shared<MockIpcClientProxy>();
    std::shared_ptr<IpcClientProxy> ipcClientProxy = DeviceManagerImpl::GetInstance().ipcClientProxy_;
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = mockInstance;
    EXPECT_CALL(*mockInstance, SendRequest(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(ERR_DM_INIT_FAILED));
    int32_t ret = DeviceManager::GetInstance().ImportCredential(packName, credentialInfo);
    ASSERT_EQ(ret, ERR_DM_IPC_SEND_REQUEST_FAILED);
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = ipcClientProxy;
}

/**
 * @tc.name: DeleteCredential_001
 * @tc.desc: 1. set packName null
 *              set deleteInfo null
 *           2. call DeviceManagerImpl::DeleteCredential with parameter
 *           3. check ret is ERR_DM_INPUT_PARA_INVALID
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, DeleteCredential_001, testing::ext::TestSize.Level0)
{
    std::string packName;
    std::string deleteInfo;
    int32_t ret = DeviceManager::GetInstance().DeleteCredential(packName, deleteInfo);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: DeleteCredential_002
 * @tc.desc: 1. set packName not null
 *              set deleteInfo not null
 *           2. MOCK IpcClientProxy SendRequest return ERR_DM_IPC_SEND_REQUEST_FAILED
 *           3. call DeviceManagerImpl::DeleteCredential with parameter
 *           4. check ret is ERR_DM_IPC_SEND_REQUEST_FAILED
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, DeleteCredential_002, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::string deleteInfo = R"({"processType":1,"authType":1,"userId":"123"})";
    std::shared_ptr<MockIpcClientProxy> mockInstance = std::make_shared<MockIpcClientProxy>();
    std::shared_ptr<IpcClientProxy> ipcClientProxy = DeviceManagerImpl::GetInstance().ipcClientProxy_;
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = mockInstance;
    EXPECT_CALL(*mockInstance, SendRequest(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(ERR_DM_IPC_SEND_REQUEST_FAILED));
    int32_t ret = DeviceManager::GetInstance().DeleteCredential(packName, deleteInfo);
    ASSERT_EQ(ret, ERR_DM_IPC_SEND_REQUEST_FAILED);
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = ipcClientProxy;
}

/**
 * @tc.name: DeleteCredential_003
 * @tc.desc: 1. set packName not null
 *              set deleteInfo not null
 *           2. MOCK IpcClientProxy SendRequest return DM_OK
 *           3. call DeviceManagerImpl::DeleteCredential with parameter
 *           4. check ret is DM_OK
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, DeleteCredential_003, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::string deleteInfo = R"({"processType":1,"authType":1,"userId":"123"})";
    std::shared_ptr<MockIpcClientProxy> mockInstance = std::make_shared<MockIpcClientProxy>();
    std::shared_ptr<IpcClientProxy> ipcClientProxy = DeviceManagerImpl::GetInstance().ipcClientProxy_;
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = mockInstance;
    EXPECT_CALL(*mockInstance, SendRequest(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(DM_OK));
    int32_t ret = DeviceManager::GetInstance().DeleteCredential(packName, deleteInfo);
    ASSERT_EQ(ret, DM_OK);
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = ipcClientProxy;
}

/**
 * @tc.name: DeleteCredential_004
 * @tc.desc: 1. set packName not null
 *              set credentialInfo not null
 *           2. MOCK IpcClientProxy SendRequest return ERR_DM_INIT_FAILED
 *           3. call DeviceManagerImpl::DeleteCredential with parameter
 *           4. check ret is ERR_DM_IPC_SEND_REQUEST_FAILED
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, DeleteCredential_004, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::string deleteInfo = R"({"processType":1,"authType":1,"userId":"123"})";
    std::shared_ptr<MockIpcClientProxy> mockInstance = std::make_shared<MockIpcClientProxy>();
    std::shared_ptr<IpcClientProxy> ipcClientProxy = DeviceManagerImpl::GetInstance().ipcClientProxy_;
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = mockInstance;
    EXPECT_CALL(*mockInstance, SendRequest(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(ERR_DM_INIT_FAILED));
    int32_t ret = DeviceManager::GetInstance().DeleteCredential(packName, deleteInfo);
    ASSERT_EQ(ret, ERR_DM_IPC_SEND_REQUEST_FAILED);
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = ipcClientProxy;
}

/**
 * @tc.name: RegisterCredentialCallback_001
 * @tc.desc: 1. set packName null
 *              set callback null
 *           3. call DeviceManagerImpl::RegisterCredentialCallback with parameter
 *           4. check ret is ERR_DM_INPUT_PARA_INVALID
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, RegisterCredentialCallback_001, testing::ext::TestSize.Level0)
{
    std::string packName = "";
    std::shared_ptr<CredentialCallbackTest> callback = nullptr;
    int32_t ret = DeviceManager::GetInstance().RegisterCredentialCallback(packName, callback);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: RegisterCredentialCallback_002
 * @tc.desc: 1. set packName not null
 *              set callback not null
 *           2. call DeviceManagerImpl::RegisterCredentialCallback with parameter
 *           3. check ret is DM_OK
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, RegisterCredentialCallback_002, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::shared_ptr<CredentialCallbackTest> callback = std::make_shared<CredentialCallbackTest>();
    std::shared_ptr<DmInitCallback> initCallback = std::make_shared<DmInitCallbackTest>();
    DeviceManager::GetInstance().InitDeviceManager(packName, initCallback);
    int32_t ret = DeviceManager::GetInstance().RegisterCredentialCallback(packName, callback);
    ASSERT_EQ(ret, DM_OK);
    DeviceManager::GetInstance().UnInitDeviceManager(packName);
}

/**
 * @tc.name: RegisterCredentialCallback_003
 * @tc.desc: 1. set packName not null
 *              set callback null
 *           2. call DeviceManagerImpl::RegisterCredentialCallback with parameter
 *           3. check ret is ERR_DM_INPUT_PARA_INVALID
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, RegisterCredentialCallback_003, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::shared_ptr<CredentialCallbackTest> callback = nullptr;
    int32_t ret = DeviceManager::GetInstance().RegisterCredentialCallback(packName, callback);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: RegisterCredentialCallback_004
 * @tc.desc: 1. set packName null
 *              set callback not null
 *           2. call DeviceManagerImpl::RegisterCredentialCallback with parameter
 *           3. check ret is ERR_DM_INPUT_PARA_INVALID
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, RegisterCredentialCallback_004, testing::ext::TestSize.Level0)
{
    std::string packName = "";
    std::shared_ptr<CredentialCallbackTest> callback = std::make_shared<CredentialCallbackTest>();
    int32_t ret = DeviceManager::GetInstance().RegisterCredentialCallback(packName, callback);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: UnRegisterCredentialCallback_001
 * @tc.desc: 1. set packName null
 *           2. call DeviceManagerImpl::UnRegisterCredentialCallback with parameter
 *           3. check ret is ERR_DM_INPUT_PARA_INVALID
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, UnRegisterCredentialCallback_001, testing::ext::TestSize.Level0)
{
    std::string packName = "";
    int32_t ret = DeviceManager::GetInstance().UnRegisterCredentialCallback(packName);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: UnRegisterCredentialCallback_002
 * @tc.desc: 1. set packName not null
 *           2. call DeviceManagerImpl::UnRegisterCredentialCallback with parameter
 *           3. check ret is ERR_DM_IPC_SEND_REQUEST_FAILED
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, UnRegisterCredentialCallback_002, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::shared_ptr<MockIpcClientProxy> mockInstance = std::make_shared<MockIpcClientProxy>();
    std::shared_ptr<IpcClientProxy> ipcClientProxy = DeviceManagerImpl::GetInstance().ipcClientProxy_;
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = mockInstance;
    EXPECT_CALL(*mockInstance, SendRequest(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(ERR_DM_IPC_SEND_REQUEST_FAILED));
    int32_t ret = DeviceManager::GetInstance().UnRegisterCredentialCallback(packName);
    ASSERT_EQ(ret, ERR_DM_IPC_SEND_REQUEST_FAILED);
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = ipcClientProxy;
}

/**
 * @tc.name: UnRegisterCredentialCallback_003
 * @tc.desc: 1. set packName not null
 *              set callback null
 *           2. call DeviceManagerImpl::UnRegisterCredentialCallback with parameter
 *           3. check ret is ERR_DM_IPC_SEND_REQUEST_FAILED
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, UnRegisterCredentialCallback_003, testing::ext::TestSize.Level0)
{
    // 1. set packName null
    std::string packName = "com.ohos.test";
    std::shared_ptr<MockIpcClientProxy> mockInstance = std::make_shared<MockIpcClientProxy>();
    std::shared_ptr<IpcClientProxy> ipcClientProxy = DeviceManagerImpl::GetInstance().ipcClientProxy_;
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = mockInstance;
    EXPECT_CALL(*mockInstance, SendRequest(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(ERR_DM_INIT_FAILED));
    int32_t ret = DeviceManager::GetInstance().UnRegisterCredentialCallback(packName);
    ASSERT_EQ(ret, ERR_DM_IPC_SEND_REQUEST_FAILED);
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = ipcClientProxy;
}

/**
 * @tc.name: UnRegisterCredentialCallback_004
 * @tc.desc: 1. set packName not null
 *           2. call DeviceManagerImpl::UnRegisterCredentialCallback with parameter
 *           3. check ret is DM_OK
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, UnRegisterCredentialCallback_004, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::shared_ptr<DmInitCallback> callback = std::make_shared<DmInitCallbackTest>();
    DeviceManager::GetInstance().InitDeviceManager(packName, callback);
    int32_t ret = DeviceManager::GetInstance().UnRegisterCredentialCallback(packName);
    ASSERT_EQ(ret, DM_OK);
    DeviceManager::GetInstance().UnInitDeviceManager(packName);
}

/**
 * @tc.name: OnDmServiceDied_001
 * @tc.desc: 1. mock IpcClientProxy
 *           2. call DeviceManagerImpl::OnDmServiceDied
 *           3. check ret is DM_OK
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, OnDmServiceDied_001, testing::ext::TestSize.Level0)
{
    std::shared_ptr<MockIpcClientProxy> mockInstance = std::make_shared<MockIpcClientProxy>();
    std::shared_ptr<IpcClientProxy> ipcClientProxy = DeviceManagerImpl::GetInstance().ipcClientProxy_;
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = mockInstance;
    int32_t ret = DeviceManagerImpl::GetInstance().OnDmServiceDied();
    ASSERT_EQ(ret, DM_OK);
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = ipcClientProxy;
}

/**
 * @tc.name: OnDmServiceDied_001
 * @tc.desc: 1. mock IpcClientProxy
 *           2. call DeviceManagerImpl::OnDmServiceDied
 *           3. check ret is DM_OK
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, OnDmServiceDied_002, testing::ext::TestSize.Level0)
{
    // 1. mock IpcClientProxy
    std::shared_ptr<MockIpcClientProxy> mockInstance = std::make_shared<MockIpcClientProxy>();
    std::shared_ptr<IpcClientProxy> ipcClientProxy = DeviceManagerImpl::GetInstance().ipcClientProxy_;
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = mockInstance;
    EXPECT_CALL(*mockInstance, OnDmServiceDied()).Times(1).WillOnce(testing::Return(ERR_DM_POINT_NULL));
    // 2. call DeviceManagerImpl::OnDmServiceDied
    int32_t ret = DeviceManagerImpl::GetInstance().OnDmServiceDied();
    // 3. check ret is DM_OK
    ASSERT_EQ(ret, ERR_DM_FAILED);
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = ipcClientProxy;
}

/**
 * @tc.name: NotifyEvent_001
 * @tc.desc: 1. mock IpcClientProxy
 *           2. call DeviceManagerImpl::NotifyEvent
 *           3. check ret is DM_OK
 * deviceTypeId
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerImplTest, NotifyEvent_001, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    int32_t eventId = DM_NOTIFY_EVENT_ONDEVICEREADY;
    std::string event = R"({"extra": {"deviceId": "123"})";
    std::shared_ptr<MockIpcClientProxy> mockInstance = std::make_shared<MockIpcClientProxy>();
    std::shared_ptr<IpcClientProxy> ipcClientProxy = DeviceManagerImpl::GetInstance().ipcClientProxy_;
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = mockInstance;
    EXPECT_CALL(*mockInstance, SendRequest(testing::_, testing::_, testing::_))
                .Times(1).WillOnce(testing::Return(DM_OK));
    int32_t ret = DeviceManager::GetInstance().NotifyEvent(packName, eventId, event);
    ASSERT_EQ(ret, DM_OK);
    DeviceManagerImpl::GetInstance().ipcClientProxy_ = ipcClientProxy;
}

/**
 * @tc.name: NotifyEvent_002
 * @tc.desc: 1. mock IpcClientProxy
 *           2. call DeviceManagerImpl::NotifyEvent
 *           3. check ret is ERR_DM_INPUT_PARA_INVALID
 * deviceTypeId
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerImplTest, NotifyEvent_002, testing::ext::TestSize.Level0)
{
    std::string packName = "";
    int32_t eventId = DM_NOTIFY_EVENT_ONDEVICEREADY;
    std::string event = R"({"extra": {"deviceId": "123"})";
    int32_t ret = DeviceManager::GetInstance().NotifyEvent(packName, eventId, event);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: NotifyEvent_003
 * @tc.desc: 1. mock IpcClientProxy
 *           2. call DeviceManagerImpl::NotifyEvent
 *           3. check ret is ERR_DM_INPUT_PARA_INVALID
 * deviceTypeId
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerImplTest, NotifyEvent_003, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    int32_t eventId = DM_NOTIFY_EVENT_START;
    std::string event = R"({"extra": {"deviceId": "123"})";
    int32_t ret = DeviceManager::GetInstance().NotifyEvent(packName, eventId, event);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: NotifyEvent_004
 * @tc.desc: 1. mock IpcClientProxy
 *           2. call DeviceManagerImpl::NotifyEvent
 *           3. check ret is ERR_DM_INPUT_PARA_INVALID
 * deviceTypeId
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerImplTest, NotifyEvent_004, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    int32_t eventId = DM_NOTIFY_EVENT_BUTT;
    std::string event = R"({"extra": {"deviceId": "123"})";
    int32_t ret = DeviceManager::GetInstance().NotifyEvent(packName, eventId, event);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: CheckAPIAccessPermission_001
 * @tc.desc: 1. InitDeviceManager
 *           2. call DeviceManagerImpl::CheckAPIAccessPermission
 *           3. check ret is DM_OK
 *           4. UnInitDeviceManager
 * deviceTypeId
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerImplTest, CheckAPIAccessPermission_001, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::shared_ptr<CredentialCallbackTest> callback = std::make_shared<CredentialCallbackTest>();
    std::shared_ptr<DmInitCallback> initCallback = std::make_shared<DmInitCallbackTest>();
    DeviceManager::GetInstance().InitDeviceManager(packName, initCallback);
    int32_t ret = DeviceManager::GetInstance().CheckAPIAccessPermission();
    ASSERT_EQ(ret, DM_OK);
    DeviceManager::GetInstance().UnInitDeviceManager(packName);
}

/**
 * @tc.name: RegisterDevStatusCallback_001
 * @tc.desc: 1. InitDeviceManager
 *           2. call DeviceManagerImpl::RegisterDevStatusCallback
 *           3. check ret is ERR_DM_INPUT_PARA_INVALID
 * deviceTypeId
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerImplTest, RegisterDevStatusCallback_001, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    std::string extra;
    std::shared_ptr<DeviceStatusCallback> callback = nullptr;
    int32_t ret = DeviceManager::GetInstance().RegisterDevStatusCallback(pkgName, extra, callback);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: RegisterDevStatusCallback_002
 * @tc.desc: 1. InitDeviceManager
 *           2. call DeviceManagerImpl::RegisterDevStatusCallback
 *           3. check ret is ERR_DM_INPUT_PARA_INVALID
 * deviceTypeId
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerImplTest, RegisterDevStatusCallback_002, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::string extra;
    std::shared_ptr<DeviceStatusCallback> callback = nullptr;
    int32_t ret = DeviceManager::GetInstance().RegisterDevStatusCallback(packName, extra, callback);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: RegisterDevStatusCallback_003
 * @tc.desc: 1. InitDeviceManager
 *           2. call DeviceManagerImpl::RegisterDevStatusCallback
 *           3. check ret is DM_OK
 * deviceTypeId
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerImplTest, RegisterDevStatusCallback_003, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::string extra;
    std::shared_ptr<DeviceStatusCallback> callback = std::make_shared<DeviceStatusCallbackTest>();
    int32_t ret = DeviceManager::GetInstance().RegisterDevStatusCallback(packName, extra, callback);
    ASSERT_EQ(ret, DM_OK);
}

/**
 * @tc.name: UnRegisterDevStatusCallback_001
 * @tc.desc: 1. InitDeviceManager
 *           2. call DeviceManagerImpl::UnRegisterDevStatusCallback
 *           3. check ret is ERR_DM_INPUT_PARA_INVALID
 * deviceTypeId
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerImplTest, UnRegisterDevStatusCallback_001, testing::ext::TestSize.Level0)
{
    std::string packName;
    int32_t ret = DeviceManager::GetInstance().UnRegisterDevStatusCallback(packName);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: UnRegisterDevStatusCallback_002
 * @tc.desc: 1. InitDeviceManager
 *           2. call DeviceManagerImpl::UnRegisterDevStatusCallback
 *           3. check ret is DM_OK
 * deviceTypeId
 * @tc.type: FUNC
 */
HWTEST_F(DeviceManagerImplTest, UnRegisterDevStatusCallback_002, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    int32_t ret = DeviceManager::GetInstance().UnRegisterDevStatusCallback(packName);
    ASSERT_EQ(ret, DM_OK);
}

/**
 * @tc.name: StartDeviceDiscovery_104
 * @tc.desc: 1. set packName null
 *              set subscribeId 0
 *              set filterOptions null
 *              set callback not null
 *           2. InitDeviceManager return DM_OK
 *           3. call DeviceManagerImpl::StartDeviceDiscovery with parameter
 *           4. check ret is ERR_DM_INPUT_PARA_INVALID
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, StartDeviceDiscovery_104, testing::ext::TestSize.Level0)
{
    std::string packName;
    uint16_t subscribeId = 0;
    std::string filterOptions;
    std::shared_ptr<DiscoveryCallback> callback = std::make_shared<DeviceDiscoveryCallbackTest>();
    DmDeviceBasicInfo deviceBasicInfo;
    callback->OnDeviceFound(subscribeId, deviceBasicInfo);
    std::shared_ptr<DmInitCallback> initcallback = std::make_shared<DmInitCallbackTest>();
    int32_t ret = DeviceManager::GetInstance().InitDeviceManager(packName, initcallback);
    ret = DeviceManager::GetInstance().StartDeviceDiscovery(packName, subscribeId, filterOptions, callback);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
    DeviceManager::GetInstance().UnInitDeviceManager(packName);
}

/**
 * @tc.name: StartDeviceDiscovery_105
 * @tc.desc: 1. set packName not null
 *              set subscribeId 0
 *              set filterOptions null
 *              set callback not null
 *           2. InitDeviceManager return DM_OK
 *           3. call DeviceManagerImpl::StartDeviceDiscovery with parameter
 *           4. check ret is ERR_DM_INPUT_PARA_INVALID
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, StartDeviceDiscovery_105, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    uint16_t subscribeId = 0;
    std::string filterOptions;
    std::shared_ptr<DiscoveryCallback> callback = nullptr;
    int32_t ret = DeviceManager::GetInstance().StartDeviceDiscovery(packName, subscribeId, filterOptions, callback);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

/**
 * @tc.name: StartDeviceDiscovery_106
 * @tc.desc: 1. set packName not null
 *              set subscribeId 0
 *              set filterOptions not null
 *              set callback not null
 *           2. InitDeviceManager return DM_OK
 *           3. call DeviceManagerImpl::StartDeviceDiscovery with parameter
 *           4. check ret is DM_OK
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, StartDeviceDiscovery_106, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    uint16_t subscribeId = -1;
    std::string filterOptions = "filterOptions";
    DeviceManagerImpl::GetInstance().subscribIdMap_.clear();
    std::shared_ptr<DiscoveryCallback> callback = std::make_shared<DeviceDiscoveryCallbackTest>();
    std::shared_ptr<DmInitCallback> initcallback = std::make_shared<DmInitCallbackTest>();
    int32_t ret = DeviceManager::GetInstance().InitDeviceManager(packName, initcallback);
    ret = DeviceManager::GetInstance().StartDeviceDiscovery(packName, subscribeId, filterOptions, callback);
    ASSERT_NE(ret, DM_OK);
    DeviceManager::GetInstance().UnInitDeviceManager(packName);
}

/**
 * @tc.name: RequestCredential_101
 * @tc.desc: 1. set packName not null
 *              set reqJsonStr not null
 *           2. MOCK IpcClientProxy SendRequest return DM_OK
 *           3. call DeviceManagerImpl::RequestCredential with parameter
 *           4. check ret is DM_OK
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, RequestCredential_101, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::string returnJsonStr;
    std::shared_ptr<DmInitCallback> callback = std::make_shared<DmInitCallbackTest>();
    DeviceManager::GetInstance().InitDeviceManager(packName, callback);
    int32_t ret = DeviceManager::GetInstance().RequestCredential(packName, returnJsonStr);
    DeviceManager::GetInstance().UnInitDeviceManager(packName);
    ASSERT_EQ(ret, DM_OK);
}

/**
 * @tc.name: CheckCredential_101
 * @tc.desc: 1. set packName not null
 *              set credentialInfo not null
 *           2. MOCK IpcClientProxy SendRequest return DM_OK
 *           3. call DeviceManagerImpl::ImportCredential with parameter
 *           4. check ret is DM_OK
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, CheckCredential_101, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::string credentialInfo = "{\n}";
    std::string returnJsonStr;
    std::shared_ptr<DmInitCallback> callback = std::make_shared<DmInitCallbackTest>();
    DeviceManager::GetInstance().InitDeviceManager(packName, callback);
    int32_t ret = DeviceManager::GetInstance().CheckCredential(packName, credentialInfo, returnJsonStr);
    DeviceManager::GetInstance().UnInitDeviceManager(packName);
    ASSERT_EQ(ret, DM_OK);
}

/**
 * @tc.name: ImportCredential_101
 * @tc.desc: 1. set packName not null
 *              set credentialInfo not null
 *           2. MOCK IpcClientProxy SendRequest return DM_OK
 *           3. call DeviceManagerImpl::ImportCredential with parameter
 *           4. check ret is DM_OK
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, ImportCredential_101, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::string credentialInfo = R"(
    {
        "processType": 1,
        "authType": 1,
        "userId": "123",
        "credentialData":
        [
            {
                "credentialType": 1,
                "credentialId": "104",
                "authCode": "10F9F0576E61730193D2052B7F771887124A68F1607EFCF7796C1491F834CD92",
                "serverPk": "",
                "pkInfoSignature": "",
                "pkInfo": "",
                "peerDeviceId": ""
            }
        ]
    }
    )";
    std::string returnJsonStr;
    std::shared_ptr<DmInitCallback> callback = std::make_shared<DmInitCallbackTest>();
    DeviceManager::GetInstance().InitDeviceManager(packName, callback);
    int32_t ret = DeviceManager::GetInstance().ImportCredential(packName, credentialInfo, returnJsonStr);
    DeviceManager::GetInstance().UnInitDeviceManager(packName);
    ASSERT_EQ(ret, DM_OK);
}

/**
 * @tc.name: DeleteCredential_101
 * @tc.desc: 1. set packName not null
 *              set deleteInfo not null
 *           2. MOCK IpcClientProxy SendRequest return DM_OK
 *           3. call DeviceManagerImpl::DeleteCredential with parameter
 *           4. check ret is DM_OK
 * deviceTypeId
 * @tc.type: FUNC
 * @tc.require: AR000GHSJK
 */
HWTEST_F(DeviceManagerImplTest, DeleteCredential_101, testing::ext::TestSize.Level0)
{
    std::string packName = "com.ohos.test";
    std::string credentialInfo = R"({"isDeleteAll":true})";
    std::string returnJsonStr;
    std::shared_ptr<DmInitCallback> callback = std::make_shared<DmInitCallbackTest>();
    DeviceManager::GetInstance().InitDeviceManager(packName, callback);
    int32_t ret = DeviceManager::GetInstance().DeleteCredential(packName, credentialInfo, returnJsonStr);
    DeviceManager::GetInstance().UnInitDeviceManager(packName);
    ASSERT_EQ(ret, DM_OK);
}
HWTEST_F(DeviceManagerImplTest, VerifyAuthentication001, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    std::string authPara;
    std::shared_ptr<VerifyAuthCallback> callback = nullptr;
    int32_t ret = DeviceManager::GetInstance().VerifyAuthentication(pkgName, authPara, callback);
    ASSERT_EQ(ret, DM_OK);
}

HWTEST_F(DeviceManagerImplTest, GetFaParam001, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    DmAuthParam dmFaParam;
    int32_t ret = DeviceManager::GetInstance().GetFaParam(pkgName, dmFaParam);
    ASSERT_EQ(ret, DM_OK);
}

HWTEST_F(DeviceManagerImplTest, RegisterDevStateCallback001, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    std::string extra;
    int32_t ret = DeviceManager::GetInstance().RegisterDevStateCallback(pkgName, extra);
    ASSERT_EQ(ret, DM_OK);
}

HWTEST_F(DeviceManagerImplTest, UnRegisterDevStateCallback001, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    std::string extra;
    int32_t ret = DeviceManager::GetInstance().UnRegisterDevStateCallback(pkgName, extra);
    ASSERT_EQ(ret, DM_OK);
}

HWTEST_F(DeviceManagerImplTest, RequestCredential001, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    std::string reqJsonStr;
    std::string returnJsonStr;
    int32_t ret = DeviceManager::GetInstance().RequestCredential(pkgName, reqJsonStr, returnJsonStr);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DeviceManagerImplTest, RequestCredential002, testing::ext::TestSize.Level0)
{
    std::string pkgName = "pkgName";
    std::string reqJsonStr;
    std::string returnJsonStr;
    int32_t ret = DeviceManager::GetInstance().RequestCredential(pkgName, reqJsonStr, returnJsonStr);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DeviceManagerImplTest, RequestCredential003, testing::ext::TestSize.Level0)
{
    std::string pkgName = "pkgName";
    std::string reqJsonStr = "reqJsonStr";
    std::string returnJsonStr;
    int32_t ret = DeviceManager::GetInstance().RequestCredential(pkgName, reqJsonStr, returnJsonStr);
    EXPECT_NE(ret, DM_OK);
}

HWTEST_F(DeviceManagerImplTest, ImportCredential001, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    std::string credentialInfo;
    int32_t ret = DeviceManager::GetInstance().ImportCredential(pkgName, credentialInfo);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DeviceManagerImplTest, ImportCredential002, testing::ext::TestSize.Level0)
{
    std::string pkgName = "pkgName";
    std::string credentialInfo;
    int32_t ret = DeviceManager::GetInstance().ImportCredential(pkgName, credentialInfo);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DeviceManagerImplTest, ImportCredential003, testing::ext::TestSize.Level0)
{
    std::string pkgName = "pkgName";
    std::string credentialInfo = "credentialInfo";
    int32_t ret = DeviceManager::GetInstance().ImportCredential(pkgName, credentialInfo);
    EXPECT_NE(ret, DM_OK);
}

HWTEST_F(DeviceManagerImplTest, DeleteCredential001, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    std::string deleteInfo;
    int32_t ret = DeviceManager::GetInstance().DeleteCredential(pkgName, deleteInfo);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DeviceManagerImplTest, DeleteCredential002, testing::ext::TestSize.Level0)
{
    std::string pkgName = "pkgName";
    std::string deleteInfo;
    int32_t ret = DeviceManager::GetInstance().DeleteCredential(pkgName, deleteInfo);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DeviceManagerImplTest, DeleteCredential003, testing::ext::TestSize.Level0)
{
    std::string pkgName = "pkgName";
    std::string deleteInfo = "deleteInfo";
    int32_t ret = DeviceManager::GetInstance().DeleteCredential(pkgName, deleteInfo);
    EXPECT_NE(ret, DM_OK);
}

HWTEST_F(DeviceManagerImplTest, RegisterCredentialCallback001, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    std::shared_ptr<CredentialCallback> callback = nullptr;
    int32_t ret = DeviceManager::GetInstance().RegisterCredentialCallback(pkgName, callback);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DeviceManagerImplTest, RegisterCredentialCallback002, testing::ext::TestSize.Level0)
{
    std::string pkgName = "pkgName";
    std::shared_ptr<CredentialCallback> callback = nullptr;
    int32_t ret = DeviceManager::GetInstance().RegisterCredentialCallback(pkgName, callback);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DeviceManagerImplTest, UnRegisterCredentialCallback001, testing::ext::TestSize.Level0)
{
    std::string pkgName;
    int32_t ret = DeviceManager::GetInstance().UnRegisterCredentialCallback(pkgName);
    ASSERT_EQ(ret, ERR_DM_INPUT_PARA_INVALID);
}

HWTEST_F(DeviceManagerImplTest, UnRegisterCredentialCallback002, testing::ext::TestSize.Level0)
{
    DeviceManagerImpl::GetInstance().ipcClientProxy_->ipcClientManager_ = nullptr;
    std::string pkgName = "pkgName";
    int32_t ret = DeviceManager::GetInstance().UnRegisterCredentialCallback(pkgName);
    EXPECT_EQ(ret, ERR_DM_IPC_SEND_REQUEST_FAILED);
    DeviceManagerImpl::GetInstance().ipcClientProxy_->ipcClientManager_ = std::make_shared<IpcClientManager>();
}

HWTEST_F(DeviceManagerImplTest, CheckRelatedDevice001, testing::ext::TestSize.Level0)
{
    std::string udid;
    std::string bundleName = "pkgName";
    bool ret = DeviceManager::GetInstance().CheckRelatedDevice(udid, bundleName);
    EXPECT_EQ(ret, false);
}

HWTEST_F(DeviceManagerImplTest, CheckRelatedDevice002, testing::ext::TestSize.Level0)
{
    std::string udid = "123";
    std::string bundleName = "pkgName";
    bool ret = DeviceManager::GetInstance().CheckRelatedDevice(udid, bundleName);
    EXPECT_NE(ret, true);
}

} // namespace
} // namespace DistributedHardware
} // namespace OHOS