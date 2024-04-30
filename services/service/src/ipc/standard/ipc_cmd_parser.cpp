/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <memory>

#include "device_manager_ipc_interface_code.h"
#include "device_manager_service.h"
#include "dm_anonymous.h"
#include "dm_constants.h"
#include "dm_device_info.h"
#include "dm_log.h"
#include "dm_subscribe_info.h"
#include "dm_publish_info.h"
#include "ipc_acl_profile_req.h"
#include "ipc_cmd_register.h"
#include "ipc_def.h"
#include "ipc_create_pin_holder_req.h"
#include "ipc_destroy_pin_holder_req.h"
#include "ipc_notify_auth_result_req.h"
#include "ipc_notify_bind_result_req.h"
#include "ipc_notify_credential_req.h"
#include "ipc_notify_device_found_req.h"
#include "ipc_notify_device_discovery_req.h"
#include "ipc_notify_device_state_req.h"
#include "ipc_notify_discover_result_req.h"
#include "ipc_notify_publish_result_req.h"
#include "ipc_notify_pin_holder_event_req.h"
#include "ipc_server_client_proxy.h"
#include "ipc_server_stub.h"

#include "nlohmann/json.hpp"

namespace OHOS {
namespace DistributedHardware {
bool EncodeDmDeviceInfo(const DmDeviceInfo &devInfo, MessageParcel &parcel)
{
    bool bRet = true;
    std::string deviceIdStr(devInfo.deviceId);
    bRet = (bRet && parcel.WriteString(deviceIdStr));
    std::string deviceNameStr(devInfo.deviceName);
    bRet = (bRet && parcel.WriteString(deviceNameStr));
    bRet = (bRet && parcel.WriteUint16(devInfo.deviceTypeId));
    std::string networkIdStr(devInfo.networkId);
    bRet = (bRet && parcel.WriteString(networkIdStr));
    bRet = (bRet && parcel.WriteInt32(devInfo.range));
    bRet = (bRet && parcel.WriteInt32(devInfo.networkType));
    bRet = (bRet && parcel.WriteInt32(devInfo.authForm));
    bRet = (bRet && parcel.WriteString(devInfo.extraData));
    return bRet;
}

bool EncodeDmDeviceBasicInfo(const DmDeviceBasicInfo &devInfo, MessageParcel &parcel)
{
    bool bRet = true;
    std::string deviceIdStr(devInfo.deviceId);
    bRet = (bRet && parcel.WriteString(deviceIdStr));
    std::string deviceNameStr(devInfo.deviceName);
    bRet = (bRet && parcel.WriteString(deviceNameStr));
    bRet = (bRet && parcel.WriteUint16(devInfo.deviceTypeId));
    std::string networkIdStr(devInfo.networkId);
    bRet = (bRet && parcel.WriteString(networkIdStr));
    return bRet;
}

bool EncodePeerTargetId(const PeerTargetId &targetId, MessageParcel &parcel)
{
    bool bRet = true;
    bRet = (bRet && parcel.WriteString(targetId.deviceId));
    bRet = (bRet && parcel.WriteString(targetId.brMac));
    bRet = (bRet && parcel.WriteString(targetId.bleMac));
    bRet = (bRet && parcel.WriteString(targetId.wifiIp));
    bRet = (bRet && parcel.WriteUint16(targetId.wifiPort));
    return bRet;
}

void DecodePeerTargetId(MessageParcel &parcel, PeerTargetId &targetId)
{
    targetId.deviceId = parcel.ReadString();
    targetId.brMac = parcel.ReadString();
    targetId.bleMac = parcel.ReadString();
    targetId.wifiIp = parcel.ReadString();
    targetId.wifiPort = parcel.ReadUint16();
}

ON_IPC_SET_REQUEST(SERVER_DEVICE_STATE_NOTIFY, std::shared_ptr<IpcReq> pBaseReq, MessageParcel &data)
{
    if (pBaseReq == nullptr) {
        return ERR_DM_FAILED;
    }

    std::shared_ptr<IpcNotifyDeviceStateReq> pReq = std::static_pointer_cast<IpcNotifyDeviceStateReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    int32_t deviceState = pReq->GetDeviceState();
    DmDeviceInfo deviceInfo = pReq->GetDeviceInfo();
    DmDeviceBasicInfo deviceBasicInfo = pReq->GetDeviceBasicInfo();
    if (!data.WriteString(pkgName)) {
        LOGE("write pkgName failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt32(deviceState)) {
        LOGE("write state failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!EncodeDmDeviceInfo(deviceInfo, data)) {
        LOGE("write dm device info failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteRawData(&deviceBasicInfo, sizeof(DmDeviceBasicInfo))) {
        LOGE("write deviceBasicInfo failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_READ_RESPONSE(SERVER_DEVICE_STATE_NOTIFY, MessageParcel &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    if (pBaseRsp == nullptr) {
        LOGE("pBaseRsp is null");
        return ERR_DM_FAILED;
    }
    pBaseRsp->SetErrCode(reply.ReadInt32());
    return DM_OK;
}

ON_IPC_SET_REQUEST(SERVER_DEVICE_FOUND, std::shared_ptr<IpcReq> pBaseReq, MessageParcel &data)
{
    if (pBaseReq == nullptr) {
        return ERR_DM_FAILED;
    }

    std::shared_ptr<IpcNotifyDeviceFoundReq> pReq = std::static_pointer_cast<IpcNotifyDeviceFoundReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    uint16_t subscribeId = pReq->GetSubscribeId();
    DmDeviceInfo deviceInfo = pReq->GetDeviceInfo();
    DmDeviceBasicInfo devBasicInfo = pReq->GetDeviceBasicInfo();
    if (!data.WriteString(pkgName)) {
        LOGE("write pkgName failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt16((int16_t)subscribeId)) {
        LOGE("write subscribeId failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!EncodeDmDeviceInfo(deviceInfo, data)) {
        LOGE("write dm device info failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!EncodeDmDeviceBasicInfo(devBasicInfo, data)) {
        LOGE("write dm device basic info failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_READ_RESPONSE(SERVER_DEVICE_FOUND, MessageParcel &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    if (pBaseRsp == nullptr) {
        LOGE("pBaseRsp is null");
        return ERR_DM_FAILED;
    }
    pBaseRsp->SetErrCode(reply.ReadInt32());
    return DM_OK;
}

ON_IPC_SET_REQUEST(SERVER_DEVICE_DISCOVERY, std::shared_ptr<IpcReq> pBaseReq, MessageParcel &data)
{
    if (pBaseReq == nullptr) {
        return ERR_DM_FAILED;
    }

    std::shared_ptr<IpcNotifyDeviceDiscoveryReq> pReq = std::static_pointer_cast<IpcNotifyDeviceDiscoveryReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    uint16_t subscribeId = pReq->GetSubscribeId();
    DmDeviceBasicInfo deviceBasicInfo = pReq->GetDeviceBasicInfo();
    if (!data.WriteString(pkgName)) {
        LOGE("write pkgName failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt16((int16_t)subscribeId)) {
        LOGE("write subscribeId failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteRawData(&deviceBasicInfo, sizeof(DmDeviceBasicInfo))) {
        LOGE("write deviceBasicInfo failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_READ_RESPONSE(SERVER_DEVICE_DISCOVERY, MessageParcel &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    if (pBaseRsp == nullptr) {
        LOGE("pBaseRsp is null");
        return ERR_DM_FAILED;
    }
    pBaseRsp->SetErrCode(reply.ReadInt32());
    return DM_OK;
}

ON_IPC_SET_REQUEST(SERVER_DISCOVER_FINISH, std::shared_ptr<IpcReq> pBaseReq, MessageParcel &data)
{
    if (pBaseReq == nullptr) {
        return ERR_DM_FAILED;
    }
    std::shared_ptr<IpcNotifyDiscoverResultReq> pReq = std::static_pointer_cast<IpcNotifyDiscoverResultReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    uint16_t subscribeId = pReq->GetSubscribeId();
    int32_t result = pReq->GetResult();
    if (!data.WriteString(pkgName)) {
        LOGE("write pkgName failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt16((int16_t)subscribeId)) {
        LOGE("write subscribeId failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_READ_RESPONSE(SERVER_DISCOVER_FINISH, MessageParcel &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    if (pBaseRsp == nullptr) {
        LOGE("pBaseRsp is null");
        return ERR_DM_FAILED;
    }
    pBaseRsp->SetErrCode(reply.ReadInt32());
    return DM_OK;
}

ON_IPC_SET_REQUEST(SERVER_PUBLISH_FINISH, std::shared_ptr<IpcReq> pBaseReq, MessageParcel &data)
{
    if (pBaseReq == nullptr) {
        return ERR_DM_FAILED;
    }
    std::shared_ptr<IpcNotifyPublishResultReq> pReq = std::static_pointer_cast<IpcNotifyPublishResultReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    int32_t publishId = pReq->GetPublishId();
    int32_t result = pReq->GetResult();
    if (!data.WriteString(pkgName)) {
        LOGE("write pkgName failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt32(publishId)) {
        LOGE("write publishId failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_READ_RESPONSE(SERVER_PUBLISH_FINISH, MessageParcel &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    if (pBaseRsp == nullptr) {
        LOGE("pBaseRsp is null");
        return ERR_DM_FAILED;
    }
    pBaseRsp->SetErrCode(reply.ReadInt32());
    return DM_OK;
}

ON_IPC_SET_REQUEST(SERVER_AUTH_RESULT, std::shared_ptr<IpcReq> pBaseReq, MessageParcel &data)
{
    if (pBaseReq == nullptr) {
        return ERR_DM_FAILED;
    }
    std::shared_ptr<IpcNotifyAuthResultReq> pReq = std::static_pointer_cast<IpcNotifyAuthResultReq>(pBaseReq);

    std::string pkgName = pReq->GetPkgName();
    std::string deviceId = pReq->GetDeviceId();
    std::string token = pReq->GetPinToken();
    int32_t status = pReq->GetStatus();
    int32_t reason = pReq->GetReason();
    if (!data.WriteString(pkgName)) {
        LOGE("write pkgName failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteString(deviceId)) {
        LOGE("write deviceId failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteString(token)) {
        LOGE("write token failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt32(status)) {
        LOGE("write status failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt32(reason)) {
        LOGE("write reason failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_READ_RESPONSE(SERVER_AUTH_RESULT, MessageParcel &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    if (pBaseRsp == nullptr) {
        LOGE("pBaseRsp is null");
        return ERR_DM_FAILED;
    }
    pBaseRsp->SetErrCode(reply.ReadInt32());
    return DM_OK;
}

ON_IPC_SET_REQUEST(SERVER_DEVICE_FA_NOTIFY, std::shared_ptr<IpcReq> pBaseReq, MessageParcel &data)
{
    if (pBaseReq == nullptr) {
        return ERR_DM_FAILED;
    }

    std::shared_ptr<IpcNotifyDMFAResultReq> pReq = std::static_pointer_cast<IpcNotifyDMFAResultReq>(pBaseReq);

    std::string packagname = pReq->GetPkgName();
    std::string paramJson = pReq->GetJsonParam();
    if (!data.WriteString(packagname)) {
        LOGE("write pkgName failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteString(paramJson)) {
        LOGE("write paramJson failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_READ_RESPONSE(SERVER_DEVICE_FA_NOTIFY, MessageParcel &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    if (pBaseRsp == nullptr) {
        LOGE("pBaseRsp is null");
        return ERR_DM_FAILED;
    }
    pBaseRsp->SetErrCode(reply.ReadInt32());
    return DM_OK;
}

ON_IPC_CMD(GET_TRUST_DEVICE_LIST, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string extra = data.ReadString();
    bool isRefresh = data.ReadBool();
    DeviceManagerService::GetInstance().ShiftLNNGear(pkgName, pkgName, isRefresh);
    std::vector<DmDeviceInfo> deviceList;
    int32_t result = DeviceManagerService::GetInstance().GetTrustedDeviceList(pkgName, extra, deviceList);
    if (!reply.WriteInt32((int32_t)deviceList.size())) {
        LOGE("write device list size failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    for (const auto &devInfo : deviceList) {
        if (!EncodeDmDeviceInfo(devInfo, reply)) {
            LOGE("write dm device info failed");
            return ERR_DM_IPC_WRITE_FAILED;
        }
    }
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(GET_AVAILABLE_DEVICE_LIST, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::vector<DmDeviceBasicInfo> deviceList;
    int32_t result = DeviceManagerService::GetInstance().GetAvailableDeviceList(pkgName, deviceList);
    int32_t infoNum = (int32_t)(deviceList.size());
    DmDeviceBasicInfo deviceBasicInfo;
    if (!reply.WriteInt32(infoNum)) {
        LOGE("write infoNum failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!deviceList.empty()) {
        for (; !deviceList.empty();) {
            deviceBasicInfo = deviceList.back();
            deviceList.pop_back();

            if (!reply.WriteRawData(&deviceBasicInfo, sizeof(DmDeviceBasicInfo))) {
                LOGE("write subscribeInfo failed");
                return ERR_DM_IPC_WRITE_FAILED;
            }
        }
    }
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(REGISTER_DEVICE_MANAGER_LISTENER, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    sptr<IRemoteObject> listener = data.ReadRemoteObject();
    if (listener == nullptr) {
        LOGE("read remote object failed.");
        return ERR_DM_POINT_NULL;
    }
    sptr<IpcServerClientProxy> callback(new IpcServerClientProxy(listener));
    if (callback == nullptr) {
        LOGE("create ipc server client proxy failed.");
        return ERR_DM_POINT_NULL;
    }
    DeviceManagerService::GetInstance().RegisterDeviceManagerListener(pkgName);
    int32_t result = IpcServerStub::GetInstance().RegisterDeviceManagerListener(pkgName, callback);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(UNREGISTER_DEVICE_MANAGER_LISTENER, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    DeviceManagerService::GetInstance().UnRegisterDeviceManagerListener(pkgName);
    int32_t result = IpcServerStub::GetInstance().UnRegisterDeviceManagerListener(pkgName);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(START_DEVICE_DISCOVER, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string extra = data.ReadString();
    DmSubscribeInfo *subscribeInfo =
        static_cast<DmSubscribeInfo *>(const_cast<void *>(data.ReadRawData(sizeof(DmSubscribeInfo))));
    int32_t result = ERR_DM_POINT_NULL;

    if (subscribeInfo != nullptr) {
        result = DeviceManagerService::GetInstance().StartDeviceDiscovery(pkgName, *subscribeInfo, extra);
    }
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(START_DEVICE_DISCOVERY, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string filterOption = data.ReadString();
    uint16_t subscribeId = data.ReadUint16();
    int32_t result = DeviceManagerService::GetInstance().StartDeviceDiscovery(pkgName, subscribeId, filterOption);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(STOP_DEVICE_DISCOVER, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    uint16_t subscribeId = data.ReadUint16();
    int32_t result = DeviceManagerService::GetInstance().StopDeviceDiscovery(pkgName, subscribeId);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(PUBLISH_DEVICE_DISCOVER, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    DmPublishInfo *publishInfo =
        static_cast<DmPublishInfo *>(const_cast<void *>(data.ReadRawData(sizeof(DmPublishInfo))));
    int32_t result = ERR_DM_POINT_NULL;

    if (publishInfo != nullptr) {
        result = DeviceManagerService::GetInstance().PublishDeviceDiscovery(pkgName, *publishInfo);
    }
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(UNPUBLISH_DEVICE_DISCOVER, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    int32_t publishId = data.ReadInt32();
    int32_t result = DeviceManagerService::GetInstance().UnPublishDeviceDiscovery(pkgName, publishId);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(AUTHENTICATE_DEVICE, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string extra = data.ReadString();
    std::string deviceId = data.ReadString();
    int32_t authType = data.ReadInt32();

    int32_t result = DM_OK;
    result = DeviceManagerService::GetInstance().AuthenticateDevice(pkgName, authType, deviceId, extra);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(UNAUTHENTICATE_DEVICE, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string deviceId = data.ReadString();
    int32_t result = DeviceManagerService::GetInstance().UnAuthenticateDevice(pkgName, deviceId);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(GET_DEVICE_INFO, MessageParcel &data, MessageParcel &reply)
{
    std::string networkId = data.ReadString();
    DmDeviceInfo deviceInfo;
    int32_t result = DeviceManagerService::GetInstance().GetDeviceInfo(networkId, deviceInfo);
    if (!EncodeDmDeviceInfo(deviceInfo, reply)) {
        LOGE("write dm device info failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(GET_LOCAL_DEVICE_INFO, MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    DmDeviceInfo localDeviceInfo;
    int32_t result = DeviceManagerService::GetInstance().GetLocalDeviceInfo(localDeviceInfo);
    if (!EncodeDmDeviceInfo(localDeviceInfo, reply)) {
        LOGE("write dm device info failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(GET_LOCAL_DEVICE_NETWORKID, MessageParcel &data, MessageParcel &reply)
{
    std::string networkId = "";
    int32_t result = DeviceManagerService::GetInstance().GetLocalDeviceNetworkId(networkId);
    if (!reply.WriteString(networkId)) {
        LOGE("write LocalDeviceNetworkId failed");
    }
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(GET_LOCAL_DEVICEID, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string deviceId = "";
    int32_t result = DeviceManagerService::GetInstance().GetLocalDeviceId(pkgName, deviceId);
    if (!reply.WriteString(deviceId)) {
        LOGE("write GetLocalDeviceId failed");
    }
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(GET_LOCAL_DEVICE_NAME, MessageParcel &data, MessageParcel &reply)
{
    std::string deviceName = "";
    int32_t result = DeviceManagerService::GetInstance().GetLocalDeviceName(deviceName);
    if (!reply.WriteString(deviceName)) {
        LOGE("write GetLocalDeviceName failed");
    }
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(GET_LOCAL_DEVICE_TYPE, MessageParcel &data, MessageParcel &reply)
{
    int32_t deviceType = 0;
    int32_t result = DeviceManagerService::GetInstance().GetLocalDeviceType(deviceType);
    if (!reply.WriteInt32(deviceType)) {
        LOGE("write GetLocalDeviceName failed");
    }
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(GET_UDID_BY_NETWORK, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string netWorkId = data.ReadString();
    std::string udid;
    int32_t result = DeviceManagerService::GetInstance().GetUdidByNetworkId(pkgName, netWorkId, udid);

    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!reply.WriteString(udid)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(GET_UUID_BY_NETWORK, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string netWorkId = data.ReadString();
    std::string uuid;
    int32_t result = DeviceManagerService::GetInstance().GetUuidByNetworkId(pkgName, netWorkId, uuid);

    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!reply.WriteString(uuid)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(SERVER_USER_AUTH_OPERATION, MessageParcel &data, MessageParcel &reply)
{
    std::string packageName = data.ReadString();
    int32_t action = data.ReadInt32();
    std::string params = data.ReadString();
    int result = DeviceManagerService::GetInstance().SetUserOperation(packageName, action, params);
    if (!reply.WriteInt32(result)) {
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return result;
}

ON_IPC_CMD(REQUEST_CREDENTIAL, MessageParcel &data, MessageParcel &reply)
{
    std::string packageName = data.ReadString();
    std::string reqParaStr = data.ReadString();
    std::map<std::string, std::string> requestParam;
    ParseMapFromJsonString(reqParaStr, requestParam);
    std::string returnJsonStr;
    int32_t ret = ERR_DM_FAILED;
    if (requestParam[DM_CREDENTIAL_TYPE] == DM_TYPE_OH) {
        ret = DeviceManagerService::GetInstance().RequestCredential(requestParam[DM_CREDENTIAL_REQJSONSTR],
                                                                    returnJsonStr);
    }
    if (requestParam[DM_CREDENTIAL_TYPE] == DM_TYPE_MINE) {
        ret = DeviceManagerService::GetInstance().MineRequestCredential(packageName, returnJsonStr);
    }
    if (!reply.WriteInt32(ret)) {
        LOGE("write ret failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (ret == DM_OK && !returnJsonStr.empty()) {
        if (!reply.WriteString(returnJsonStr)) {
            LOGE("write returnJsonStr failed");
            return ERR_DM_IPC_WRITE_FAILED;
        }
    }
    return DM_OK;
}

ON_IPC_CMD(IMPORT_CREDENTIAL, MessageParcel &data, MessageParcel &reply)
{
    std::string packageName = data.ReadString();
    std::string reqParaStr = data.ReadString();
    std::map<std::string, std::string> requestParam;
    ParseMapFromJsonString(reqParaStr, requestParam);
    std::string returnJsonStr;
    std::map<std::string, std::string> outputResult;
    int32_t ret = ERR_DM_FAILED;
    if (requestParam[DM_CREDENTIAL_TYPE] == DM_TYPE_OH) {
        ret = DeviceManagerService::GetInstance().ImportCredential(packageName, requestParam[DM_CREDENTIAL_REQJSONSTR]);
        outputResult.emplace(DM_CREDENTIAL_TYPE, DM_TYPE_OH);
    }
    if (requestParam[DM_CREDENTIAL_TYPE] == DM_TYPE_MINE) {
        ret = DeviceManagerService::GetInstance().ImportCredential(packageName, requestParam[DM_CREDENTIAL_REQJSONSTR],
                                                                   returnJsonStr);
        outputResult.emplace(DM_CREDENTIAL_TYPE, DM_TYPE_MINE);
        outputResult.emplace(DM_CREDENTIAL_RETURNJSONSTR, returnJsonStr);
    }
    if (!reply.WriteInt32(ret)) {
        LOGE("write ret failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (ret == DM_OK && !returnJsonStr.empty()) {
        std::string outParaStr = ConvertMapToJsonString(outputResult);
        if (!reply.WriteString(outParaStr)) {
        LOGE("write returnJsonStr failed");
        return ERR_DM_IPC_WRITE_FAILED;
        }
    }
    return DM_OK;
}

ON_IPC_CMD(DELETE_CREDENTIAL, MessageParcel &data, MessageParcel &reply)
{
    std::string packageName = data.ReadString();
    std::string reqParaStr = data.ReadString();
    std::map<std::string, std::string> requestParam;
    ParseMapFromJsonString(reqParaStr, requestParam);
    std::map<std::string, std::string> outputResult;
    std::string returnJsonStr;
    int32_t ret = ERR_DM_FAILED;
    if (requestParam[DM_CREDENTIAL_TYPE] == DM_TYPE_OH) {
        ret = DeviceManagerService::GetInstance().DeleteCredential(packageName, requestParam[DM_CREDENTIAL_REQJSONSTR]);
        outputResult.emplace(DM_CREDENTIAL_TYPE, DM_TYPE_OH);
    }
    if (requestParam[DM_CREDENTIAL_TYPE] == DM_TYPE_MINE) {
        ret = DeviceManagerService::GetInstance().DeleteCredential(packageName, requestParam[DM_CREDENTIAL_REQJSONSTR],
                                                                   returnJsonStr);
        outputResult.emplace(DM_CREDENTIAL_TYPE, DM_TYPE_MINE);
        outputResult.emplace(DM_CREDENTIAL_RETURNJSONSTR, returnJsonStr);
    }
    if (!reply.WriteInt32(ret)) {
        LOGE("write ret failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (ret == DM_OK && !returnJsonStr.empty()) {
        std::string outParaStr = ConvertMapToJsonString(outputResult);
        if (!reply.WriteString(outParaStr)) {
            LOGE("write returnJsonStr failed");
            return ERR_DM_IPC_WRITE_FAILED;
        }
    }
    return DM_OK;
}

ON_IPC_CMD(SERVER_GET_DMFA_INFO, MessageParcel &data, MessageParcel &reply)
{
    std::string packageName = data.ReadString();
    std::string reqJsonStr = data.ReadString();
    std::string returnJsonStr;
    int32_t ret = DeviceManagerService::GetInstance().CheckCredential(packageName, reqJsonStr, returnJsonStr);
    if (!reply.WriteInt32(ret)) {
        LOGE("write ret failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (ret == DM_OK && !returnJsonStr.empty()) {
        if (!reply.WriteString(returnJsonStr)) {
            LOGE("write returnJsonStr failed");
            return ERR_DM_IPC_WRITE_FAILED;
        }
    }
    return DM_OK;
}

ON_IPC_CMD(REGISTER_CREDENTIAL_CALLBACK, MessageParcel &data, MessageParcel &reply)
{
    std::string packageName = data.ReadString();
    int result = DeviceManagerService::GetInstance().RegisterCredentialCallback(packageName);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return result;
}

ON_IPC_CMD(UNREGISTER_CREDENTIAL_CALLBACK, MessageParcel &data, MessageParcel &reply)
{
    std::string packageName = data.ReadString();
    int result = DeviceManagerService::GetInstance().UnRegisterCredentialCallback(packageName);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return result;
}

ON_IPC_CMD(NOTIFY_EVENT, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    int32_t eventId = data.ReadInt32();
    std::string event = data.ReadString();
    int32_t result = DeviceManagerService::GetInstance().NotifyEvent(pkgName, eventId, event);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_SET_REQUEST(SERVER_CREDENTIAL_RESULT, std::shared_ptr<IpcReq> pBaseReq, MessageParcel &data)
{
    if (pBaseReq == nullptr) {
        return ERR_DM_FAILED;
    }
    std::shared_ptr<IpcNotifyCredentialReq> pReq = std::static_pointer_cast<IpcNotifyCredentialReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    int32_t action = pReq->GetCredentialAction();
    std::string credentialResult = pReq->GetCredentialResult();
    if (!data.WriteString(pkgName)) {
        LOGE("write pkgName failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt32(action)) {
        LOGE("write action failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteString(credentialResult)) {
        LOGE("write credentialResult failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }

    return DM_OK;
}

ON_IPC_READ_RESPONSE(SERVER_CREDENTIAL_RESULT, MessageParcel &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    if (pBaseRsp == nullptr) {
        LOGE("pBaseRsp is null");
        return ERR_DM_FAILED;
    }
    pBaseRsp->SetErrCode(reply.ReadInt32());
    return DM_OK;
}

ON_IPC_CMD(GET_ENCRYPTED_UUID_BY_NETWOEKID, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string networkId = data.ReadString();
    std::string uuid;

    int32_t result = DeviceManagerService::GetInstance().GetEncryptedUuidByNetworkId(pkgName, networkId, uuid);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!reply.WriteString(uuid)) {
        LOGE("write uuid failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(GENERATE_ENCRYPTED_UUID, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string uuid = data.ReadString();
    std::string appId = data.ReadString();
    std::string encryptedUuid;

    int32_t result = DeviceManagerService::GetInstance().GenerateEncryptedUuid(pkgName, uuid, appId, encryptedUuid);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!reply.WriteString(encryptedUuid)) {
        LOGE("write encryptedUuid failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(BIND_DEVICE, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string bindParam = data.ReadString();
    std::string deviceId = data.ReadString();
    int32_t bindType = data.ReadInt32();
    int32_t result = DM_OK;
    result = DeviceManagerService::GetInstance().BindDevice(pkgName, bindType, deviceId, bindParam);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(UNBIND_DEVICE, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string deviceId = data.ReadString();
    int32_t result = DeviceManagerService::GetInstance().UnBindDevice(pkgName, deviceId);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(GET_NETWORKTYPE_BY_NETWORK, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string netWorkId = data.ReadString();
    int32_t networkType = -1;
    int32_t result = DeviceManagerService::GetInstance().GetNetworkTypeByNetworkId(pkgName, netWorkId, networkType);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!reply.WriteInt32(networkType)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(REGISTER_UI_STATE_CALLBACK, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    int32_t result = DeviceManagerService::GetInstance().RegisterUiStateCallback(pkgName);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(UNREGISTER_UI_STATE_CALLBACK, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    int32_t result = DeviceManagerService::GetInstance().UnRegisterUiStateCallback(pkgName);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(IMPORT_AUTH_CODE, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string authCode = data.ReadString();
    int32_t result = DeviceManagerService::GetInstance().ImportAuthCode(pkgName, authCode);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(EXPORT_AUTH_CODE, MessageParcel &data, MessageParcel &reply)
{
    std::string authCode = "";
    int32_t result = DeviceManagerService::GetInstance().ExportAuthCode(authCode);
    if (!reply.WriteString(authCode)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(REGISTER_DISCOVERY_CALLBACK, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string discParaStr = data.ReadString();
    std::string filterOpStr = data.ReadString();
    std::map<std::string, std::string> discoverParam;
    ParseMapFromJsonString(discParaStr, discoverParam);
    std::map<std::string, std::string> filterOptions;
    ParseMapFromJsonString(filterOpStr, filterOptions);
    int32_t result = DeviceManagerService::GetInstance().EnableDiscoveryListener(pkgName, discoverParam, filterOptions);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(UNREGISTER_DISCOVERY_CALLBACK, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string extraParaStr = data.ReadString();
    std::map<std::string, std::string> extraParam;
    ParseMapFromJsonString(extraParaStr, extraParam);
    int32_t result = DeviceManagerService::GetInstance().DisableDiscoveryListener(pkgName, extraParam);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(START_DISCOVERING, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string discParaStr = data.ReadString();
    std::string filterOpStr = data.ReadString();
    std::map<std::string, std::string> discoverParam;
    ParseMapFromJsonString(discParaStr, discoverParam);
    std::map<std::string, std::string> filterOptions;
    ParseMapFromJsonString(filterOpStr, filterOptions);
    int32_t result = DeviceManagerService::GetInstance().StartDiscovering(pkgName, discoverParam, filterOptions);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(STOP_DISCOVERING, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string discParaStr = data.ReadString();
    std::map<std::string, std::string> discoverParam;
    ParseMapFromJsonString(discParaStr, discoverParam);
    int32_t result = DeviceManagerService::GetInstance().StopDiscovering(pkgName, discoverParam);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(START_ADVERTISING, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string adverParaStr = data.ReadString();
    std::map<std::string, std::string> advertiseParam;
    ParseMapFromJsonString(adverParaStr, advertiseParam);
    int32_t result = DeviceManagerService::GetInstance().StartAdvertising(pkgName, advertiseParam);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(STOP_ADVERTISING, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string adverParaStr = data.ReadString();
    std::map<std::string, std::string> advertiseParam;
    ParseMapFromJsonString(adverParaStr, advertiseParam);
    int32_t result = DeviceManagerService::GetInstance().StopAdvertising(pkgName, advertiseParam);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(BIND_TARGET, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    PeerTargetId targetId;
    DecodePeerTargetId(data, targetId);
    std::string bindParamStr = data.ReadString();
    std::map<std::string, std::string> bindParam;
    ParseMapFromJsonString(bindParamStr, bindParam);
    int32_t result = DeviceManagerService::GetInstance().BindTarget(pkgName, targetId, bindParam);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(UNBIND_TARGET, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    PeerTargetId targetId;
    DecodePeerTargetId(data, targetId);
    std::string unbindParamStr = data.ReadString();
    std::map<std::string, std::string> unbindParam;
    ParseMapFromJsonString(unbindParamStr, unbindParam);
    int32_t result = DeviceManagerService::GetInstance().UnbindTarget(pkgName, targetId, unbindParam);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_SET_REQUEST(BIND_TARGET_RESULT, std::shared_ptr<IpcReq> pBaseReq, MessageParcel &data)
{
    if (pBaseReq == nullptr) {
        return ERR_DM_FAILED;
    }
    std::shared_ptr<IpcNotifyBindResultReq> pReq = std::static_pointer_cast<IpcNotifyBindResultReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    PeerTargetId targetId = pReq->GetPeerTargetId();
    int32_t result = pReq->GetResult();
    int32_t status = pReq->GetStatus();
    std::string content = pReq->GetContent();

    if (!data.WriteString(pkgName)) {
        LOGE("write bind pkgName failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!EncodePeerTargetId(targetId, data)) {
        LOGE("write bind peer target id failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt32(result)) {
        LOGE("write bind result code failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt32(status)) {
        LOGE("write bind result status failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteString(content)) {
        LOGE("write bind result content failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_READ_RESPONSE(BIND_TARGET_RESULT, MessageParcel &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    if (pBaseRsp == nullptr) {
        LOGE("pBaseRsp is null");
        return ERR_DM_FAILED;
    }
    pBaseRsp->SetErrCode(reply.ReadInt32());
    return DM_OK;
}

ON_IPC_SET_REQUEST(UNBIND_TARGET_RESULT, std::shared_ptr<IpcReq> pBaseReq, MessageParcel &data)
{
    if (pBaseReq == nullptr) {
        return ERR_DM_FAILED;
    }
    std::shared_ptr<IpcNotifyBindResultReq> pReq = std::static_pointer_cast<IpcNotifyBindResultReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    PeerTargetId targetId = pReq->GetPeerTargetId();
    int32_t result = pReq->GetResult();
    std::string content = pReq->GetContent();

    if (!data.WriteString(pkgName)) {
        LOGE("write unbind pkgName failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!EncodePeerTargetId(targetId, data)) {
        LOGE("write unbind peer target id failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt32(result)) {
        LOGE("write unbind result code failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteString(content)) {
        LOGE("write unbind result content failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_READ_RESPONSE(UNBIND_TARGET_RESULT, MessageParcel &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    if (pBaseRsp == nullptr) {
        LOGE("pBaseRsp is null");
        return ERR_DM_FAILED;
    }
    pBaseRsp->SetErrCode(reply.ReadInt32());
    return DM_OK;
}

ON_IPC_CMD(REGISTER_PIN_HOLDER_CALLBACK, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    int32_t result = DeviceManagerService::GetInstance().RegisterPinHolderCallback(pkgName);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(CREATE_PIN_HOLDER, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    PeerTargetId targetId;
    DecodePeerTargetId(data, targetId);
    std::string payload = data.ReadString();
    DmPinType pinType = static_cast<DmPinType>(data.ReadInt32());
    int32_t result = DeviceManagerService::GetInstance().CreatePinHolder(pkgName, targetId, pinType, payload);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(DESTROY_PIN_HOLDER, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    PeerTargetId targetId;
    DecodePeerTargetId(data, targetId);
    DmPinType pinType = static_cast<DmPinType>(data.ReadInt32());
    std::string payload = data.ReadString();
    int32_t result = DeviceManagerService::GetInstance().DestroyPinHolder(pkgName, targetId, pinType, payload);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_SET_REQUEST(SERVER_CREATE_PIN_HOLDER, std::shared_ptr<IpcReq> pBaseReq, MessageParcel &data)
{
    if (pBaseReq == nullptr) {
        return ERR_DM_FAILED;
    }
    std::shared_ptr<IpcCreatePinHolderReq> pReq = std::static_pointer_cast<IpcCreatePinHolderReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    std::string deviceId = pReq->GetDeviceId();
    int32_t pinType = pReq->GetPinType();
    std::string payload = pReq->GetPayload();

    if (!data.WriteString(pkgName)) {
        LOGE("write pkgName failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteString(deviceId)) {
        LOGE("write deviceId failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt32(pinType)) {
        LOGE("write pinType failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteString(payload)) {
        LOGE("write payload failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_READ_RESPONSE(SERVER_CREATE_PIN_HOLDER, MessageParcel &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    if (pBaseRsp == nullptr) {
        LOGE("pBaseRsp is null");
        return ERR_DM_FAILED;
    }
    pBaseRsp->SetErrCode(reply.ReadInt32());
    return DM_OK;
}

ON_IPC_SET_REQUEST(SERVER_DESTROY_PIN_HOLDER, std::shared_ptr<IpcReq> pBaseReq, MessageParcel &data)
{
    if (pBaseReq == nullptr) {
        return ERR_DM_FAILED;
    }
    std::shared_ptr<IpcDestroyPinHolderReq> pReq = std::static_pointer_cast<IpcDestroyPinHolderReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    int32_t pinType = pReq->GetPinType();
    std::string payload = pReq->GetPayload();

    if (!data.WriteString(pkgName)) {
        LOGE("write pkgName failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt32(pinType)) {
        LOGE("write pinType failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteString(payload)) {
        LOGE("write payload failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_READ_RESPONSE(SERVER_DESTROY_PIN_HOLDER, MessageParcel &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    if (pBaseRsp == nullptr) {
        LOGE("pBaseRsp is null");
        return ERR_DM_FAILED;
    }
    pBaseRsp->SetErrCode(reply.ReadInt32());
    return DM_OK;
}

ON_IPC_SET_REQUEST(SERVER_CREATE_PIN_HOLDER_RESULT, std::shared_ptr<IpcReq> pBaseReq, MessageParcel &data)
{
    if (pBaseReq == nullptr) {
        return ERR_DM_FAILED;
    }
    std::shared_ptr<IpcNotifyPublishResultReq> pReq = std::static_pointer_cast<IpcNotifyPublishResultReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    int32_t result = pReq->GetResult();

    if (!data.WriteString(pkgName)) {
        LOGE("write pkgName failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_READ_RESPONSE(SERVER_CREATE_PIN_HOLDER_RESULT, MessageParcel &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    if (pBaseRsp == nullptr) {
        LOGE("pBaseRsp is null");
        return ERR_DM_FAILED;
    }
    pBaseRsp->SetErrCode(reply.ReadInt32());
    return DM_OK;
}

ON_IPC_SET_REQUEST(SERVER_DESTROY_PIN_HOLDER_RESULT, std::shared_ptr<IpcReq> pBaseReq, MessageParcel &data)
{
    if (pBaseReq == nullptr) {
        return ERR_DM_FAILED;
    }
    std::shared_ptr<IpcNotifyPublishResultReq> pReq = std::static_pointer_cast<IpcNotifyPublishResultReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    int32_t result = pReq->GetResult();

    if (!data.WriteString(pkgName)) {
        LOGE("write pkgName failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_READ_RESPONSE(SERVER_DESTROY_PIN_HOLDER_RESULT, MessageParcel &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    if (pBaseRsp == nullptr) {
        LOGE("pBaseRsp is null");
        return ERR_DM_FAILED;
    }
    pBaseRsp->SetErrCode(reply.ReadInt32());
    return DM_OK;
}

ON_IPC_CMD(DP_ACL_ADD, MessageParcel &data, MessageParcel &reply)
{
    std::string udid = data.ReadString();
    int32_t result = DeviceManagerService::GetInstance().DpAclAdd(udid);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(GET_SECURITY_LEVEL, MessageParcel &data, MessageParcel &reply)
{
    std::string pkgName = data.ReadString();
    std::string networkId = data.ReadString();
    int32_t securityLevel = -1;
    int32_t result = DeviceManagerService::GetInstance().GetDeviceSecurityLevel(pkgName, networkId, securityLevel);
    if (!reply.WriteInt32(result)) {
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!reply.WriteInt32(securityLevel)) {
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_SET_REQUEST(SERVER_ON_PIN_HOLDER_EVENT, std::shared_ptr<IpcReq> pBaseReq, MessageParcel &data)
{
    if (pBaseReq == nullptr) {
        return ERR_DM_FAILED;
    }
    std::shared_ptr<IpcNotifyPinHolderEventReq> pReq = std::static_pointer_cast<IpcNotifyPinHolderEventReq>(pBaseReq);
    std::string pkgName = pReq->GetPkgName();
    int32_t pinHolderEvent = pReq->GetPinHolderEvent();
    int32_t result = pReq->GetResult();
    std::string content = pReq->GetContent();

    if (!data.WriteString(pkgName)) {
        LOGE("write pkgName failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteInt32(pinHolderEvent)) {
        LOGE("write pinHolderEvent failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    if (!data.WriteString(content)) {
        LOGE("write content failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_READ_RESPONSE(SERVER_ON_PIN_HOLDER_EVENT, MessageParcel &reply, std::shared_ptr<IpcRsp> pBaseRsp)
{
    if (pBaseRsp == nullptr) {
        LOGE("pBaseRsp is null");
        return ERR_DM_FAILED;
    }
    pBaseRsp->SetErrCode(reply.ReadInt32());
    return DM_OK;
}

ON_IPC_CMD(IS_SAME_ACCOUNT, MessageParcel &data, MessageParcel &reply)
{
    std::string udid = data.ReadString();
    int32_t result = DeviceManagerService::GetInstance().IsSameAccount(udid);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed.");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(CHECK_API_PERMISSION, MessageParcel &data, MessageParcel &reply)
{
    int32_t permissionLevel = data.ReadInt32();
    int32_t result = DeviceManagerService::GetInstance().CheckApiPermission(permissionLevel);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}

ON_IPC_CMD(CHECK_RELATED_DEVICE, MessageParcel &data, MessageParcel &reply)
{
    std::string udid = data.ReadString();
    std::string bundleName = data.ReadString();
    int32_t result = DeviceManagerService::GetInstance().CheckRelatedDevice(udid, bundleName);
    if (!reply.WriteInt32(result)) {
        LOGE("write result failed.");
        return ERR_DM_IPC_WRITE_FAILED;
    }
    return DM_OK;
}
} // namespace DistributedHardware
} // namespace OHOS