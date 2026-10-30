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
#include "ipc_client_stub_3rd_Refactor.h"

#include <cstring>
#include <securec.h>

#include "device_manager_notify_3rd.h"
#include "dm_auth_info_3rd.h"
#include "dm_error_type_3rd.h"
#include "dm_log_3rd.h"
#include "ipc_interface_code_3rd.h"
#include "ipc_object_stub.h"
#include "message_option.h"
#include "message_parcel.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
constexpr int32_t MAX_TRUST_3RD_DEVICE_SIZE = 500;
constexpr uint32_t MAX_SESSION_KEY_LENGTH = 512;
}

int32_t IpcClientStub3rdRefactor::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (GetDescriptor() != remoteDescriptor) {
        LOGI("ReadInterfaceToken fail!");
        return ERR_DM_IPC_READ_FAILED;
    }
    switch (code) {
        case ON_AUTH_RESULT_3RD:
            OnAuthResult(data, reply, option);
            break;
        case ON_AUTH_RESULT_TRUST_3RD:
            OnAuthResultTrust(data, reply, option);
            break;
        default:
            LOGE("invalid request code.");
            break;
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

void IpcClientStub3rdRefactor::OnAuthResult(MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    ProcessInfo3rd processInfo {};
    DecodeProcessInfo(data, processInfo);
    int32_t result = data.ReadInt32();
    int32_t status = data.ReadInt32();
    std::string authContent = data.ReadString();
    DeviceManagerNotify3rd::GetInstance().OnAuthResult(processInfo, result, status, authContent);
    reply.WriteInt32(DM_OK);
}

void IpcClientStub3rdRefactor::OnAuthResultTrust(MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    ProcessInfo3rd processInfo {};
    DecodeProcessInfo(data, processInfo);
    int32_t result = data.ReadInt32();
    int32_t status = data.ReadInt32();
    std::string authContent = data.ReadString();
    std::vector<TrustDeviceInfo3rd> deviceInfos;
    DecodeTrustDeviceInfos(data, deviceInfos);
    DeviceManagerNotify3rd::GetInstance().OnAuthResult(
        processInfo, result, status, deviceInfos, authContent);
    reply.WriteInt32(DM_OK);
}

void IpcClientStub3rdRefactor::DecodeProcessInfo(MessageParcel &parcel, ProcessInfo3rd &processInfo)
{
    processInfo.tokenId = parcel.ReadUint32();
    processInfo.uid = parcel.ReadInt32();
    processInfo.businessName = parcel.ReadString();
    processInfo.processName = parcel.ReadString();
    processInfo.userId = parcel.ReadInt32();
}

bool IpcClientStub3rdRefactor::DecodeSessionKey(MessageParcel &data, TrustDeviceInfo3rd &deviceInfo)
{
    uint32_t keyLen = data.ReadUint32();
    if (keyLen == 0 || keyLen > MAX_SESSION_KEY_LENGTH) {
        LOGE("SessionKey len invalid.");
        return false;
    }
    const uint8_t *tempSk = data.ReadBuffer(keyLen);
    if (tempSk == nullptr) {
        LOGE("read sessionKey failed.");
        return false;
    }
    deviceInfo.sessionKey.key = static_cast<uint8_t *>(calloc(keyLen, sizeof(uint8_t)));
    if (deviceInfo.sessionKey.key == nullptr) {
        LOGE("calloc sessionKey failed.");
        return false;
    }
    if (memcpy_s(deviceInfo.sessionKey.key, keyLen, tempSk, keyLen) != DM_OK) {
        LOGE("memcpy_s failed.");
        (void)memset_s(deviceInfo.sessionKey.key, keyLen, 0, keyLen);
        free(deviceInfo.sessionKey.key);
        deviceInfo.sessionKey.key = nullptr;
        deviceInfo.sessionKey.keyLen = 0;
        return false;
    }
    deviceInfo.sessionKey.keyLen = keyLen;
    return true;
}

void IpcClientStub3rdRefactor::DecodeTrustDeviceInfos(MessageParcel &data,
    std::vector<TrustDeviceInfo3rd> &deviceInfos)
{
    int32_t listSize = data.ReadInt32();
    if (listSize < 0 || listSize > MAX_TRUST_3RD_DEVICE_SIZE) {
        LOGE("invalid list size.");
        return;
    }
    for (int32_t i = 0; i < listSize; ++i) {
        TrustDeviceInfo3rd deviceInfo {};
        deviceInfo.trustDeviceId = data.ReadString();
        deviceInfo.deviceName = data.ReadString();
        deviceInfo.businessName = data.ReadString();
        deviceInfo.extra = data.ReadString();
        deviceInfo.deviceTypeId = data.ReadUint16();
        deviceInfo.sessionKeyId = data.ReadInt32();
        deviceInfo.userId = data.ReadInt32();
        deviceInfo.bindLevel = data.ReadInt32();
        deviceInfo.bindType = data.ReadInt32();
        deviceInfo.createTime = data.ReadInt64();
        if (!DecodeSessionKey(data, deviceInfo)) {
            continue;
        }
        deviceInfos.push_back(deviceInfo);
    }
}
} // namespace DistributedHardware
} // namespace OHOS
