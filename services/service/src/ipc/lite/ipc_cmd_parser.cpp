/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "device_manager_ipc_interface_code.h"
#include "device_manager_service.h"
#include "dm_anonymous.h"
#include "dm_constants.h"
#include "dm_log.h"
#include "ipc_cmd_register.h"
#include "ipc_def.h"
#include "ipc_notify_device_found_req.h"
#include "ipc_notify_device_state_req.h"
#include "ipc_notify_discover_result_req.h"
#include "ipc_server_stub.h"

namespace OHOS {
namespace DistributedHardware {
int32_t SetRspErrCode(IpcIo &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    if (pBaseRsp == nullptr) {
        LOGE("pBaseRsp is null");
        return ERR_DM_FAILED;
    }
    int32_t ret = 0;
    ReadInt32(&reply, &ret);
    pBaseRsp->SetErrCode(ret);
    return DM_OK;
}

bool EncodeDmDeviceInfo(const DmDeviceInfo &devInfo, IpcIo &reply)
{
    bool bRet = true;
    std::string deviceIdStr(devInfo.deviceId);
    bRet = (bRet && WriteString(&reply, deviceIdStr.c_str()));
    std::string deviceNameStr(devInfo.deviceName);
    bRet = (bRet && WriteString(&reply, deviceNameStr.c_str()));
    bRet = (bRet && WriteUint16(&reply, devInfo.deviceTypeId));
    std::string networkIdStr(devInfo.networkId);
    bRet = (bRet && WriteString(&reply, networkIdStr.c_str()));
    bRet = (bRet && WriteInt32(&reply, devInfo.range));
    bRet = (bRet && WriteInt32(&reply, devInfo.networkType));
    bRet = (bRet && WriteInt32(&reply, devInfo.authForm));
    bRet = (bRet && WriteString(&reply, devInfo.extraData.c_str()));
    return bRet;
}

ON_IPC_SET_REQUEST(SERVER_DEVICE_STATE_NOTIFY, std::shared_ptr<IpcReq> pBaseReq, IpcIo &request, uint8_t *buffer,
                   size_t buffLen)
{
    std::shared_ptr<IpcNotifyDeviceStateReq> pReq = std::static_pointer_cast<IpcNotifyDeviceStateReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    int32_t deviceState = pReq->GetDeviceState();
    DmDeviceInfo deviceInfo = pReq->GetDeviceInfo();

    IpcIoInit(&request, buffer, buffLen, 0);
    WriteString(&request, pkgName.c_str());
    WriteInt32(&request, deviceState);
    EncodeDmDeviceInfo(deviceInfo, request);
    return DM_OK;
}

ON_IPC_READ_RESPONSE(SERVER_DEVICE_STATE_NOTIFY, IpcIo &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    return SetRspErrCode(reply, pBaseRsp);
}

ON_IPC_SET_REQUEST(SERVER_DEVICE_FOUND, std::shared_ptr<IpcReq> pBaseReq, IpcIo &request, uint8_t *buffer,
                   size_t buffLen)
{
    std::shared_ptr<IpcNotifyDeviceFoundReq> pReq = std::static_pointer_cast<IpcNotifyDeviceFoundReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    uint16_t subscribeId = pReq->GetSubscribeId();
    DmDeviceInfo deviceInfo = pReq->GetDeviceInfo();

    IpcIoInit(&request, buffer, buffLen, 0);
    WriteString(&request, pkgName.c_str());
    WriteUint16(&request, subscribeId);
    EncodeDmDeviceInfo(deviceInfo, request);
    return DM_OK;
}

ON_IPC_READ_RESPONSE(SERVER_DEVICE_FOUND, IpcIo &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    return SetRspErrCode(reply, pBaseRsp);
}

ON_IPC_SET_REQUEST(SERVER_DISCOVER_FINISH, std::shared_ptr<IpcReq> pBaseReq, IpcIo &request, uint8_t *buffer,
                   size_t buffLen)
{
    std::shared_ptr<IpcNotifyDiscoverResultReq> pReq = std::static_pointer_cast<IpcNotifyDiscoverResultReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    uint16_t subscribeId = pReq->GetSubscribeId();
    int32_t result = pReq->GetResult();

    IpcIoInit(&request, buffer, buffLen, 0);
    WriteString(&request, pkgName.c_str());
    WriteUint16(&request, subscribeId);
    WriteInt32(&request, result);
    return DM_OK;
}

ON_IPC_READ_RESPONSE(SERVER_DISCOVER_FINISH, IpcIo &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    return SetRspErrCode(reply, pBaseRsp);
}

ON_IPC_SERVER_CMD(REGISTER_DEVICE_MANAGER_LISTENER, IpcIo &req, IpcIo &reply)
{
    LOGI("start to register device manager service listener.");
    int32_t errCode = RegisterDeviceManagerListener(&req, &reply);
    WriteInt32(&reply, errCode);
}

ON_IPC_SERVER_CMD(UNREGISTER_DEVICE_MANAGER_LISTENER, IpcIo &req, IpcIo &reply)
{
    LOGI("start to unregister device manager service listener.");
    int32_t errCode = UnRegisterDeviceManagerListener(&req, &reply);
    WriteInt32(&reply, errCode);
}

ON_IPC_SERVER_CMD(GET_LOCAL_DEVICE_NETWORKID, IpcIo &req, IpcIo &reply)
{
    LOGI("enter GetLocalDeviceNetworkId.");
    (void)req;
    std::string networkId;
    int32_t ret = DeviceManagerService::GetInstance().GetLocalDeviceNetworkId(networkId);
    WriteString(&reply, networkId.c_str());
    WriteInt32(&reply, ret);
}

ON_IPC_SERVER_CMD(GET_LOCAL_DEVICEID, IpcIo &req, IpcIo &reply)
{
    LOGI("enter GetLocalDeviceId.");
    std::string pkgName = (const char *)ReadString(&req, nullptr);
    std::string deviceId;
    int32_t ret = DeviceManagerService::GetInstance().GetLocalDeviceId(pkgName, deviceId);
    WriteString(&reply, deviceId.c_str());
    WriteInt32(&reply, ret);
}

ON_IPC_SERVER_CMD(GET_LOCAL_DEVICE_NAME, IpcIo &req, IpcIo &reply)
{
    LOGI("enter GetLocalDeviceName.");
    std::string deviceName;
    int32_t ret = DeviceManagerService::GetInstance().GetLocalDeviceName(deviceName);
    WriteString(&reply, deviceName.c_str());
    WriteInt32(&reply, ret);
}

ON_IPC_SERVER_CMD(GET_LOCAL_DEVICE_TYPE, IpcIo &req, IpcIo &reply)
{
    LOGI("enter GetLocalDeviceType.");
    int32_t deviceType = 0;
    int32_t ret = DeviceManagerService::GetInstance().GetLocalDeviceType(deviceType);
    WriteInt32(&reply, deviceType);
    WriteInt32(&reply, ret);
}

ON_IPC_SERVER_CMD(GET_DEVICE_INFO, IpcIo &req, IpcIo &reply)
{
    LOGI("enter GetDeviceInfo.");
    std::string pkgName = (const char*)ReadString(&req, nullptr);
    std::string networkId = (const char*)ReadString(&req, nullptr);
    DmDeviceInfo deviceInfo;
    int32_t ret = DeviceManagerService::GetInstance().GetDeviceInfo(networkId, deviceInfo);
    EncodeDmDeviceInfo(deviceInfo, reply);
    WriteInt32(&reply, ret);
}

ON_IPC_SERVER_CMD(GET_AVAILABLE_DEVICE_LIST, IpcIo &req, IpcIo &reply)
{
    LOGI("enter get available device list.");
    std::string pkgName = (const char *)ReadString(&req, nullptr);
    std::vector<DmDeviceBasicInfo> deviceList;
    int32_t ret = DeviceManagerService::GetInstance().GetAvailableDeviceList(pkgName, deviceList);
    WriteInt32(&reply, ret);
    WriteInt32(&reply, deviceList.size());
    if (ret == DM_OK && deviceList.size() > 0) {
        WriteRawData(&reply, deviceList.data(), sizeof(DmDeviceBasicInfo) * deviceList.size());
    }
}

ON_IPC_SERVER_CMD(GET_TRUST_DEVICE_LIST, IpcIo &req, IpcIo &reply)
{
    LOGI("enter get trust device list.");
    std::string pkgName = (const char *)ReadString(&req, nullptr);
    std::string extra = (const char *)ReadString(&req, nullptr);
    std::vector<DmDeviceInfo> deviceList;
    int32_t ret = DeviceManagerService::GetInstance().GetTrustedDeviceList(pkgName, extra, deviceList);
    WriteInt32(&reply, ret);
    WriteInt32(&reply, deviceList.size());
    if (ret == DM_OK && deviceList.size() > 0) {
        for (const auto &devInfo : deviceList) {
            if (!EncodeDmDeviceInfo(devInfo, reply)) {
                LOGE("write dm device info failed");
            }
        }
    }
}

ON_IPC_SERVER_CMD(START_DEVICE_DISCOVERY, IpcIo &req, IpcIo &reply)
{
    LOGI("StartDeviceDiscovery service listener.");
    std::string pkgName = (const char *)ReadString(&req, nullptr);
    std::string extra = (const char *)ReadString(&req, nullptr);
    uint16_t subscribeId = 0;
    ReadUint16(&req, &subscribeId);
    int32_t ret = DeviceManagerService::GetInstance().StartDeviceDiscovery(pkgName, subscribeId, extra);
    WriteInt32(&reply, ret);
}

ON_IPC_SERVER_CMD(STOP_DEVICE_DISCOVER, IpcIo &req, IpcIo &reply)
{
    LOGI("StopDeviceDiscovery service listener.");
    std::string pkgName = (const char *)ReadString(&req, nullptr);
    uint16_t subscribeId = 0;
    ReadUint16(&req, &subscribeId);
    int32_t ret = DeviceManagerService::GetInstance().StopDeviceDiscovery(pkgName, subscribeId);
    WriteInt32(&reply, ret);
}

ON_IPC_SERVER_CMD(REQUEST_CREDENTIAL, IpcIo &req, IpcIo &reply)
{
    LOGI("request credential service listener.");
    std::string pkgName = (const char *)ReadString(&req, nullptr);
    std::string reqParaStr = (const char *)ReadString(&req, nullptr);
    std::map<std::string, std::string> requestParam;
    ParseMapFromJsonString(reqParaStr, requestParam);
    std::string returnJsonStr;
    int32_t ret = DM_OK;
    if (requestParam[DM_CREDENTIAL_TYPE] == DM_TYPE_MINE) {
        DeviceManagerService::GetInstance().MineRequestCredential(pkgName, returnJsonStr);
    }
    WriteInt32(&reply, ret);
    if (ret == DM_OK) {
        WriteString(&reply, returnJsonStr.c_str());
    }
}

ON_IPC_SERVER_CMD(SERVER_GET_DMFA_INFO, IpcIo &req, IpcIo &reply)
{
    LOGI("check credential service listener.");
    std::string pkgName = (const char *)ReadString(&req, nullptr);
    std::string reqJsonStr = (const char *)ReadString(&req, nullptr);
    std::string returnJsonStr;
    int32_t ret = DeviceManagerService::GetInstance().CheckCredential(pkgName, reqJsonStr, returnJsonStr);
    WriteInt32(&reply, ret);
    if (ret == DM_OK) {
        WriteString(&reply, returnJsonStr.c_str());
    }
}

ON_IPC_SERVER_CMD(IMPORT_CREDENTIAL, IpcIo &req, IpcIo &reply)
{
    LOGI("import credential service listener.");
    std::string pkgName = (const char *)ReadString(&req, nullptr);
    std::string reqParaStr = (const char *)ReadString(&req, nullptr);
    std::map<std::string, std::string> requestParam;
    ParseMapFromJsonString(reqParaStr, requestParam);
    std::string returnJsonStr;
    std::string outParamStr;
    int32_t ret = DM_OK;
    if (requestParam[DM_CREDENTIAL_TYPE] == DM_TYPE_MINE) {
        DeviceManagerService::GetInstance().ImportCredential(pkgName, requestParam[DM_CREDENTIAL_REQJSONSTR],
                                                             returnJsonStr);
        std::map<std::string, std::string> outputResult;
        outputResult.emplace(DM_CREDENTIAL_TYPE, DM_TYPE_MINE);
        outputResult.emplace(DM_CREDENTIAL_RETURNJSONSTR, returnJsonStr);
        outParamStr = ConvertMapToJsonString(outputResult);
    }
    WriteInt32(&reply, ret);
    if (ret == DM_OK) {
        WriteString(&reply, outParamStr.c_str());
    }
}

ON_IPC_SERVER_CMD(DELETE_CREDENTIAL, IpcIo &req, IpcIo &reply)
{
    LOGI("import credential service listener.");
    std::string pkgName = (const char *)ReadString(&req, nullptr);
    std::string reqParaStr = (const char *)ReadString(&req, nullptr);
    std::map<std::string, std::string> requestParam;
    ParseMapFromJsonString(reqParaStr, requestParam);
    std::string returnJsonStr;
    std::string outParamStr;
    int32_t ret = DM_OK;
    if (requestParam[DM_CREDENTIAL_TYPE] == DM_TYPE_MINE) {
        DeviceManagerService::GetInstance().DeleteCredential(pkgName, requestParam[DM_CREDENTIAL_REQJSONSTR],
                                                             returnJsonStr);
        std::map<std::string, std::string> outputResult;
        outputResult.emplace(DM_CREDENTIAL_TYPE, DM_TYPE_MINE);
        outputResult.emplace(DM_CREDENTIAL_RETURNJSONSTR, returnJsonStr);
        outParamStr = ConvertMapToJsonString(outputResult);
    }
    WriteInt32(&reply, ret);
    if (ret == DM_OK) {
        WriteString(&reply, outParamStr.c_str());
    }
}
} // namespace DistributedHardware
} // namespace OHOS
