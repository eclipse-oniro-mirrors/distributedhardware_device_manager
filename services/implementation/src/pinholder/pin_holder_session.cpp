/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "pin_holder_session.h"

#include "dm_anonymous.h"
#include "dm_constants.h"
#include "dm_log.h"
#include "nlohmann/json.hpp"
#include "softbus_connector.h"

namespace OHOS {
namespace DistributedHardware {
std::shared_ptr<ISoftbusSessionCallback> PinHolderSession::sessionCallback_ = nullptr;
PinHolderSession::PinHolderSession()
{
    LOGD("PinHolderSession constructor.");
}

PinHolderSession::~PinHolderSession()
{
    LOGD("PinHolderSession destructor.");
}

int32_t PinHolderSession::RegisterSessionCallback(std::shared_ptr<ISoftbusSessionCallback> callback)
{
    sessionCallback_ = callback;
    return DM_OK;
}

int32_t PinHolderSession::UnRegisterSessionCallback()
{
    sessionCallback_ = nullptr;
    return DM_OK;
}

int32_t PinHolderSession::OpenSessionServer(const PeerTargetId &targetId)
{
    int32_t sessionId = -1;
    ConnectionAddr addrInfo;
    if (GetAddrByTargetId(targetId, addrInfo) != DM_OK) {
        LOGE("[SOFTBUS]open session error, sessionId: %d.", sessionId);
    }
    sessionId = ::OpenAuthSession(DM_PIN_HOLDER_SESSION_NAME, &addrInfo, 1, nullptr);
    if (sessionId < 0) {
        LOGE("[SOFTBUS]open session error, sessionId: %d.", sessionId);
        return sessionId;
    }
    LOGI("OpenAuthSession success. sessionId: %d.", sessionId);
    return sessionId;
}

int32_t PinHolderSession::CloseSessionServer(int32_t sessionId)
{
    LOGD("CloseSessionServer.");
    ::CloseSession(sessionId);
    return DM_OK;
}

int PinHolderSession::OnSessionOpened(int sessionId, int result)
{
    if (sessionCallback_ == nullptr) {
        LOGE("OnSessionOpened error, sessionCallback_ is nullptr.");
        return ERR_DM_FAILED;
    }
    int32_t sessionSide = GetSessionSide(sessionId);
    sessionCallback_->OnSessionOpened(sessionId, sessionSide, result);
    LOGI("OnSessionOpened, success, sessionId: %d.", sessionId);
    return DM_OK;
}

void PinHolderSession::OnSessionClosed(int sessionId)
{
    LOGI("[SOFTBUS]OnSessionClosed sessionId: %d", sessionId);
    if (sessionCallback_ == nullptr) {
        LOGE("OnSessionClosed error, sessionCallback_ is nullptr.");
        return;
    }
    sessionCallback_->OnSessionClosed(sessionId);
    return;
}

void PinHolderSession::OnBytesReceived(int sessionId, const void *data, unsigned int dataLen)
{
    if (sessionId < 0 || data == nullptr || dataLen <= 0) {
        LOGE("[SOFTBUS]fail to receive data from softbus with sessionId: %d, dataLen: %d.", sessionId, dataLen);
        return;
    }
    if (sessionCallback_ == nullptr) {
        LOGE("OnBytesReceived error, sessionCallback_ is nullptr.");
        return;
    }
    LOGI("start, sessionId: %d, dataLen: %d.", sessionId, dataLen);
    std::string message = std::string(reinterpret_cast<const char *>(data), dataLen);
    sessionCallback_->OnDataReceived(sessionId, message);
    return;
}

int32_t PinHolderSession::SendData(int32_t sessionId, const std::string &message)
{
    nlohmann::json jsonObject = nlohmann::json::parse(message, nullptr, false);
    if (jsonObject.is_discarded()) {
        LOGE("extrasJson error, message: %s.", message.c_str());
        return ERR_DM_FAILED;
    }
    if (!IsInt32(jsonObject, TAG_MSG_TYPE)) {
        LOGE("SoftbusSession::SendData err json string.");
        return ERR_DM_FAILED;
    }
    int32_t msgType = jsonObject[TAG_MSG_TYPE].get<int32_t>();
    LOGI("start, msgType: %d.", msgType);
    int32_t ret = SendBytes(sessionId, message.c_str(), strlen(message.c_str()));
    if (ret != DM_OK) {
        LOGE("[SOFTBUS]SendBytes failed, ret: %d.", ret);
        return ERR_DM_FAILED;
    }
    return ret;
}

int32_t PinHolderSession::GetAddrByTargetId(const PeerTargetId &targetId, ConnectionAddr &addr)
{
    if (!targetId.wifiIp.empty() && targetId.wifiIp.length() <= IP_STR_MAX_LEN) {
        addr.type = ConnectionAddrType::CONNECTION_ADDR_WLAN;
        memcpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, targetId.wifiIp.c_str(), targetId.wifiIp.length());
        addr.info.ip.port = targetId.wifiPort;
    } else if (!targetId.brMac.empty() && targetId.brMac.length() <= BT_MAC_LEN) {
        addr.type = ConnectionAddrType::CONNECTION_ADDR_BR;
        memcpy_s(addr.info.br.brMac, BT_MAC_LEN, targetId.brMac.c_str(), targetId.brMac.length());
    } else if (!targetId.bleMac.empty() && targetId.bleMac.length() <= BT_MAC_LEN) {
        addr.type = ConnectionAddrType::CONNECTION_ADDR_BLE;
        memcpy_s(addr.info.ble.bleMac, BT_MAC_LEN, targetId.bleMac.c_str(), targetId.bleMac.length());
    } else if (!targetId.deviceId.empty()) {
        std::string connectAddr;
        ConnectionAddr *addrInfo = SoftbusConnector::GetConnectAddr(targetId.deviceId, connectAddr);
        if (addrInfo == nullptr) {
            LOGE("GetConnectAddr failed.");
            return ERR_DM_INPUT_PARA_INVALID;
        }
        addr = *addrInfo;
    }
    return DM_OK;
}
} // namespace DistributedHardware
} // namespace OHOS