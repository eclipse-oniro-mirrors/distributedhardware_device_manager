/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "dm_crypto.h"
#include "dm_log.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace DistributedHardware {
std::shared_ptr<IPinholderSessionCallback> PinHolderSession::pinholderSessionCallback_ = nullptr;
constexpr int32_t DM_OK = 0;
constexpr int32_t ERR_DM_FAILED = -20000;
constexpr const char* TAG_MSG_TYPE = "MSG_TYPE";
constexpr const char* DM_PIN_HOLDER_SESSION_NAME = "ohos.distributedhardware.devicemanager.pinholder";
PinHolderSession::PinHolderSession()
{
    LOGD("PinHolderSession constructor.");
}

PinHolderSession::~PinHolderSession()
{
    LOGD("PinHolderSession destructor.");
}

int32_t PinHolderSession::RegisterSessionCallback(std::shared_ptr<IPinholderSessionCallback> callback)
{
    pinholderSessionCallback_ = callback;
    return DM_OK;
}

int32_t PinHolderSession::UnRegisterSessionCallback()
{
    pinholderSessionCallback_ = nullptr;
    return DM_OK;
}

int32_t PinHolderSession::OpenSessionServer(const PeerTargetId &targetId)
{
    int32_t sessionId = -1;
    ConnectionAddr addrInfo;
    if (GetAddrByTargetId(targetId, addrInfo) != DM_OK) {
        LOGE("[SOFTBUS]open session error, sessionId: %{public}d.", sessionId);
        return sessionId;
    }
    sessionId = ::OpenAuthSession(DM_PIN_HOLDER_SESSION_NAME, &addrInfo, 1, nullptr);
    if (sessionId < 0) {
        LOGE("[SOFTBUS]open session error, sessionId: %{public}d.", sessionId);
        return sessionId;
    }
    LOGI("OpenAuthSession success. sessionId: %{public}d.", sessionId);
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
    if (pinholderSessionCallback_ == nullptr) {
        LOGE("OnSessionOpened error, pinholderSessionCallback_ is nullptr.");
        return ERR_DM_FAILED;
    }
    int32_t sessionSide = GetSessionSide(sessionId);
    pinholderSessionCallback_->OnSessionOpened(sessionId, sessionSide, result);
    LOGI("OnSessionOpened, success, sessionId: %{public}d.", sessionId);
    return DM_OK;
}

void PinHolderSession::OnSessionClosed(int sessionId)
{
    LOGI("[SOFTBUS]OnSessionClosed sessionId: %{public}d", sessionId);
    if (pinholderSessionCallback_ == nullptr) {
        LOGE("OnSessionClosed error, pinholderSessionCallback_ is nullptr.");
        return;
    }
    pinholderSessionCallback_->OnSessionClosed(sessionId);
    return;
}

void PinHolderSession::OnBytesReceived(int sessionId, const void *data, unsigned int dataLen)
{
    if (sessionId < 0 || data == nullptr || dataLen <= 0) {
        LOGE("[SOFTBUS]fail to receive data from softbus with sessionId: %{public}d, dataLen: %{public}d.", sessionId,
            dataLen);
        return;
    }
    if (pinholderSessionCallback_ == nullptr) {
        LOGE("OnBytesReceived error, pinholderSessionCallback_ is nullptr.");
        return;
    }
    LOGI("start, sessionId: %{public}d, dataLen: %{public}d.", sessionId, dataLen);
    std::string message = std::string(reinterpret_cast<const char *>(data), dataLen);
    pinholderSessionCallback_->OnDataReceived(sessionId, message);
    return;
}

int32_t PinHolderSession::SendData(int32_t sessionId, const std::string &message)
{
    nlohmann::json jsonObject = nlohmann::json::parse(message, nullptr, false);
    if (jsonObject.is_discarded()) {
        LOGE("extrasJson error, message: %{public}s.", GetAnonyString(message).c_str());
        return ERR_DM_FAILED;
    }
    if (!IsInt32(jsonObject, TAG_MSG_TYPE)) {
        LOGE("SoftbusSession::SendData err json string.");
        return ERR_DM_FAILED;
    }
    int32_t msgType = jsonObject[TAG_MSG_TYPE].get<int32_t>();
    LOGI("start, msgType: %{public}d.", msgType);
    int32_t ret = SendBytes(sessionId, message.c_str(), strlen(message.c_str()));
    if (ret != DM_OK) {
        LOGE("[SOFTBUS]SendBytes failed, ret: %{public}d.", ret);
        return ERR_DM_FAILED;
    }
    return ret;
}

int32_t PinHolderSession::GetAddrByTargetId(const PeerTargetId &targetId, ConnectionAddr &addr)
{
    if (!targetId.wifiIp.empty() && targetId.wifiIp.length() <= IP_STR_MAX_LEN) {
        addr.type = ConnectionAddrType::CONNECTION_ADDR_WLAN;
        if (memcpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, targetId.wifiIp.c_str(), targetId.wifiIp.length()) != DM_OK) {
            LOGE("copy wifi data failed.");
            return ERR_DM_FAILED;
        }
        addr.info.ip.port = targetId.wifiPort;
    } else if (!targetId.brMac.empty() && targetId.brMac.length() <= BT_MAC_LEN) {
        addr.type = ConnectionAddrType::CONNECTION_ADDR_BR;
        if (memcpy_s(addr.info.br.brMac, BT_MAC_LEN, targetId.brMac.c_str(), targetId.brMac.length()) != DM_OK) {
            LOGE("copy br data failed.");
            return ERR_DM_FAILED;
        }
    } else if (!targetId.bleMac.empty() && targetId.bleMac.length() <= BT_MAC_LEN) {
        addr.type = ConnectionAddrType::CONNECTION_ADDR_BLE;
        if (memcpy_s(addr.info.ble.bleMac, BT_MAC_LEN, targetId.bleMac.c_str(), targetId.bleMac.length()) != DM_OK) {
            LOGE("copy ble data failed.");
            return ERR_DM_FAILED;
        }
        if (!targetId.deviceId.empty()) {
            Crypto::ConvertHexStringToBytes(addr.info.ble.udidHash, UDID_HASH_LEN,
                targetId.deviceId.c_str(), targetId.deviceId.length());
        }
    }
    return DM_OK;
}
} // namespace DistributedHardware
} // namespace OHOS