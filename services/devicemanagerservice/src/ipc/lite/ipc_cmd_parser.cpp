/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "ipc_cmd_register.h"

#include "device_manager_errno.h"
#include "device_manager_log.h"

#include "ipc_def.h"
#include "ipc_notify_auth_result_req.h"
#include "ipc_notify_check_auth_result_req.h"
#include "ipc_notify_device_found_req.h"
#include "ipc_notify_device_state_req.h"
#include "ipc_notify_discover_result_req.h"
#include "ipc_server_adapter.h"
#include "ipc_server_stub.h"

namespace OHOS {
namespace DistributedHardware {
ON_IPC_SET_REQUEST(SERVER_DEVICE_STATE_NOTIFY, std::shared_ptr<IpcReq> pBaseReq, IpcIo &request,
    uint8_t *buffer, size_t buffLen)
{
    std::shared_ptr<IpcNotifyDeviceStateReq> pReq = std::static_pointer_cast<IpcNotifyDeviceStateReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    int32_t deviceState = pReq->GetDeviceState();
    DmDeviceInfo deviceInfo = pReq->GetDeviceInfo();

    IpcIoInit(&request, buffer, buffLen, 0);
    IpcIoPushString(&request, pkgName.c_str());
    IpcIoPushInt32(&request, deviceState);
    IpcIoPushFlatObj(&request, &deviceInfo, sizeof(DmDeviceInfo));
    return DEVICEMANAGER_OK;
}

ON_IPC_READ_RESPONSE(SERVER_DEVICE_STATE_NOTIFY, IpcIo &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    pBaseRsp->SetErrCode(IpcIoPopInt32(&reply));
    return DEVICEMANAGER_OK;
}

ON_IPC_SET_REQUEST(SERVER_DEVICE_FOUND, std::shared_ptr<IpcReq> pBaseReq, IpcIo &request,
    uint8_t *buffer, size_t buffLen)
{
    std::shared_ptr<IpcNotifyDeviceFoundReq> pReq = std::static_pointer_cast<IpcNotifyDeviceFoundReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    uint16_t subscribeId = pReq->GetSubscribeId();
    DmDeviceInfo deviceInfo = pReq->GetDeviceInfo();

    IpcIoInit(&request, buffer, buffLen, 0);
    IpcIoPushString(&request, pkgName.c_str());
    IpcIoPushUint16(&request, subscribeId);
    IpcIoPushFlatObj(&request, &deviceInfo, sizeof(DmDeviceInfo));
    return DEVICEMANAGER_OK;
}

ON_IPC_READ_RESPONSE(SERVER_DEVICE_FOUND, IpcIo &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    pBaseRsp->SetErrCode(IpcIoPopInt32(&reply));
    return DEVICEMANAGER_OK;
}

ON_IPC_SET_REQUEST(SERVER_DISCOVER_FINISH, std::shared_ptr<IpcReq> pBaseReq, IpcIo &request,
    uint8_t *buffer, size_t buffLen)
{
    std::shared_ptr<IpcNotifyDiscoverResultReq> pReq = std::static_pointer_cast<IpcNotifyDiscoverResultReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    uint16_t subscribeId = pReq->GetSubscribeId();
    int32_t result = pReq->GetResult();

    IpcIoInit(&request, buffer, buffLen, 0);
    IpcIoPushString(&request, pkgName.c_str());
    IpcIoPushUint16(&request, subscribeId);
    IpcIoPushInt32(&request, result);
    return DEVICEMANAGER_OK;
}

ON_IPC_READ_RESPONSE(SERVER_DISCOVER_FINISH, IpcIo &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    pBaseRsp->SetErrCode(IpcIoPopInt32(&reply));
    return DEVICEMANAGER_OK;
}

ON_IPC_SET_REQUEST(SERVER_AUTH_RESULT, std::shared_ptr<IpcReq> pBaseReq, IpcIo &request,
    uint8_t *buffer, size_t buffLen)
{
    std::shared_ptr<IpcNotifyAuthResultReq> pReq = std::static_pointer_cast<IpcNotifyAuthResultReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    std::string deviceId = pReq->GetDeviceId();
    int32_t pinToken = pReq->GetPinToken();
    int32_t status = pReq->GetStatus();
    int32_t reason = pReq->GetReason();

    IpcIoInit(&request, buffer, buffLen, 0);
    IpcIoPushString(&request, pkgName.c_str());
    IpcIoPushString(&request, deviceId.c_str());
    IpcIoPushInt32(&request, pinToken);
    IpcIoPushInt32(&request, status);
    IpcIoPushInt32(&request, reason);
    return DEVICEMANAGER_OK;
}

ON_IPC_READ_RESPONSE(SERVER_AUTH_RESULT, IpcIo &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    pBaseRsp->SetErrCode(IpcIoPopInt32(&reply));
    return DEVICEMANAGER_OK;
}

ON_IPC_SET_REQUEST(SERVER_CHECK_AUTH_RESULT, std::shared_ptr<IpcReq> pBaseReq, IpcIo &request,
    uint8_t *buffer, size_t buffLen)
{
    std::shared_ptr<IpcNotifyCheckAuthResultReq> pReq = std::static_pointer_cast<IpcNotifyCheckAuthResultReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    std::string deviceId = pReq->GetDeviceId();
    int32_t result = pReq->GetResult();
    int32_t flag = pReq->GetFlag();

    IpcIoInit(&request, buffer, buffLen, 0);
    IpcIoPushString(&request, pkgName.c_str());
    IpcIoPushString(&request, deviceId.c_str());
    IpcIoPushInt32(&request, result);
    IpcIoPushInt32(&request, flag);
    return DEVICEMANAGER_OK;
}

ON_IPC_READ_RESPONSE(SERVER_CHECK_AUTH_RESULT, IpcIo &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    pBaseRsp->SetErrCode(IpcIoPopInt32(&reply));
    return DEVICEMANAGER_OK;
}

ON_IPC_SERVER_CMD(GET_TRUST_DEVICE_LIST, IpcIo &req, IpcIo &reply)
{
    DMLOG(DM_LOG_INFO, "enter GetTrustedDeviceList.");
    size_t len = 0;
    std::string pkgName = (const char *)IpcIoPopString(&req, &len);
    std::string extra = (const char *)IpcIoPopString(&req, &len);
    DmDeviceInfo *info = nullptr;
    int32_t infoNum = 0;
    int32_t ret = IpcServerAdapter::GetInstance().GetTrustedDeviceList(pkgName, extra, &info, &infoNum);
    IpcIoPushInt32(&reply, infoNum);
    if (infoNum > 0) {
        IpcIoPushFlatObj(&reply, info, sizeof(DmDeviceInfo) * infoNum);
        free(info);
    }
    IpcIoPushInt32(&reply, ret);
}

ON_IPC_SERVER_CMD(REGISTER_DEVICE_MANAGER_LISTENER, IpcIo &req, IpcIo &reply)
{
    RegisterDeviceManagerListener(&req, &reply);
}

ON_IPC_SERVER_CMD(UNREGISTER_DEVICE_MANAGER_LISTENER, IpcIo &req, IpcIo &reply)
{
    UnRegisterDeviceManagerListener(&req, &reply);
}

ON_IPC_SERVER_CMD(START_DEVICE_DISCOVER, IpcIo &req, IpcIo &reply)
{
    DMLOG(DM_LOG_INFO, "StartDeviceDiscovery service listener.");
    size_t len = 0;
    std::string pkgName = (const char *)IpcIoPopString(&req, &len);
    uint32_t size = 0;
    DmSubscribeInfo *pDmSubscribeInfo = (DmSubscribeInfo*)IpcIoPopFlatObj(&req, &size);

    int32_t ret = IpcServerAdapter::GetInstance().StartDeviceDiscovery(pkgName, *pDmSubscribeInfo);
    IpcIoPushInt32(&reply, ret);
}

ON_IPC_SERVER_CMD(STOP_DEVICE_DISCOVER, IpcIo &req, IpcIo &reply)
{
    DMLOG(DM_LOG_INFO, "StopDeviceDiscovery service listener.");
    size_t len = 0;
    std::string pkgName = (const char *)IpcIoPopString(&req, &len);
    uint16_t subscribeId = IpcIoPopUint16(&req);
    int32_t ret = IpcServerAdapter::GetInstance().StopDiscovery(pkgName, subscribeId);
    IpcIoPushInt32(&reply, ret);
}

ON_IPC_SERVER_CMD(AUTHENTICATE_DEVICE, IpcIo &req, IpcIo &reply)
{
    DMLOG(DM_LOG_INFO, "AuthenticateDevice service listener.");
    size_t len = 0;
    std::string pkgName = (const char *)IpcIoPopString(&req, &len);
    size_t extraLen = 0;
    std::string extra = (const char *)IpcIoPopString(&req, &extraLen);
    uint32_t size;
    DmDeviceInfo *deviceInfo = (DmDeviceInfo*)IpcIoPopFlatObj(&req, &size);
    DmAppImageInfo imageInfo(nullptr, 0, nullptr, 0);
    int32_t ret = IpcServerAdapter::GetInstance().AuthenticateDevice(pkgName, *deviceInfo, imageInfo, extra);
    IpcIoPushInt32(&reply, ret);
}

ON_IPC_SERVER_CMD(CHECK_AUTHENTICATION, IpcIo &req, IpcIo &reply)
{
    DMLOG(DM_LOG_INFO, "CheckAuthentication service listener.");
    size_t authParaLen = 0;
    std::string authPara = (const char *)IpcIoPopString(&req, &authParaLen);
    int32_t ret = IpcServerAdapter::GetInstance().CheckAuthentication(authPara);
    IpcIoPushInt32(&reply, ret);
}
} // namespace DistributedHardware
} // namespace OHOS
