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
#include "hichain_auth_connector.h"

#include "dm_log.h"
#include "dm_anonymous.h"
#include "hichain_connector_callback.h"
#include "parameter.h"

namespace OHOS {
namespace DistributedHardware {

const int32_t P2P_BIND = 0;
std::shared_ptr<IDmDeviceAuthCallback> HiChainAuthConnector::dmDeviceAuthCallback_ = nullptr;

int32_t HiChainAuthConnector::StartAuthDevice(int64_t requestId,
    const char* authParams, const DeviceAuthCallback* callbak)
{
    LOGI("StartAuthDevice mock.");
    (void)requestId;
    (void)authParams;
    (void)callbak;
    return DM_OK;
}
int32_t HiChainAuthConnector::ProcessAuthDevice(int64_t requestId,
    const char* authParams, const DeviceAuthCallback* callbak)
{
    LOGI("ProcessAuthDevice mock.");
    (void)requestId;
    (void)authParams;
    (void)callbak;
    return DM_OK;
}
int32_t HiChainAuthConnector::ProcessCredential(int32_t operationCode, const char* requestParams, char** returnData)
{
    LOGI("ProcessCredential mock.");
    (void)operationCode;
    (void)requestParams;
    (void)returnData;
    return DM_OK;
}

HiChainAuthConnector::HiChainAuthConnector()
{
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        LOGE("hichain InitDeviceAuthService failed, err %d.", ret);
    }
    deviceAuthCallback_ = {.onTransmit = HiChainAuthConnector::onTransmit,
                           .onSessionKeyReturned = HiChainAuthConnector::onSessionKeyReturned,
                           .onFinish = HiChainAuthConnector::onFinish,
                           .onError = HiChainAuthConnector::onError,
                           .onRequest = HiChainAuthConnector::onRequest};
    LOGI("hichain GetGaInstance success.");
}

HiChainAuthConnector::~HiChainAuthConnector()
{
    DestroyDeviceAuthService();
}

int32_t HiChainAuthConnector::RegisterHiChainAuthCallback(std::shared_ptr<IDmDeviceAuthCallback> callback)
{
    dmDeviceAuthCallback_ = callback;
    return DM_OK;
}

int32_t HiChainAuthConnector::AuthDevice(int32_t pinCode, int32_t osAccountId, std::string udid, int64_t requestId)
{
    LOGI("HiChainAuthConnector::AuthDevice start.");
    nlohmann::json authParamJson;
    authParamJson["osAccountId"] = osAccountId;
    authParamJson["pinCode"] = std::to_string(pinCode);
    authParamJson["acquireType"] = P2P_BIND;
    char *authParam = strdup(authParamJson.dump().c_str());
    LOGI("StartAuthDevice authParam %s ,requestId %d.", authParam, requestId);
    int32_t ret = StartAuthDevice(requestId, authParam, &deviceAuthCallback_);
    if (ret != HC_SUCCESS) {
        LOGE("Hichain authDevice failed, ret is %d.", ret);
        return ERR_DM_FAILED;
    }
    return DM_OK;
}

int32_t HiChainAuthConnector::ProcessAuthData(int64_t requestId, std::string authData, int32_t osAccountId)
{
    LOGI("HiChainAuthConnector::ProcessAuthData start.");
    nlohmann::json jsonObject = nlohmann::json::parse(authData, nullptr, false);
    if (jsonObject.is_discarded()) {
        LOGE("DecodeRequestAuth jsonStr error");
        return ERR_DM_FAILED;
    }
    nlohmann::json jsonAuthParam;
    jsonAuthParam["osAccountId"] = osAccountId;
    jsonAuthParam["data"] = jsonObject;
    int32_t ret = ProcessAuthDevice(requestId, authData.c_str(), &deviceAuthCallback_);
    if (ret != HC_SUCCESS) {
        LOGE("Hichain processData failed ret %d.", ret);
        return ERR_DM_FAILED;
    }
    return DM_OK;
}
 
bool HiChainAuthConnector::onTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    LOGI("AuthDevice onTransmit, requestId %d.", requestId);
    if (dmDeviceAuthCallback_ == nullptr) {
        LOGE("HiChainAuthConnector::onTransmit dmDeviceAuthCallback_ is nullptr.");
        return false;
    }
    return dmDeviceAuthCallback_->AuthDeviceTransmit(requestId, data, dataLen);
}

char *HiChainAuthConnector::onRequest(int64_t requestId, int operationCode, const char *reqParams)
{
    LOGI("HiChainAuthConnector::onRequest start.");
    (void)requestId;
    (void)reqParams;
    if (dmDeviceAuthCallback_ == nullptr) {
        LOGE("HiChainAuthConnector::onRequest dmDeviceAuthCallback_ is nullptr.");
        return nullptr;
    }
    nlohmann::json jsonObj;
    int32_t pinCode = dmDeviceAuthCallback_->GetPinCode();
    if (pinCode == ERR_DM_AUTH_NOT_START) {
        jsonObj[FIELD_CONFIRMATION] = RequestResponse::REQUEST_REJECTED;
    } else {
        jsonObj[FIELD_CONFIRMATION] = RequestResponse::REQUEST_ACCEPTED;
    }
    std::string deviceId = "";
    dmDeviceAuthCallback_->GetRemoteDeviceId(deviceId);
    jsonObj[FIELD_PIN_CODE] = std::to_string(pinCode);
    jsonObj[FIELD_PEER_CONN_DEVICE_ID] = deviceId;
    std::string jsonStr = jsonObj.dump();
    char *buffer = strdup(jsonStr.c_str());
    return buffer;
}

void HiChainAuthConnector::onFinish(int64_t requestId, int operationCode, const char *returnData)
{
    LOGI("HiChainAuthConnector::onFinish reqId:%lld, operation:%d, returnData %s.",
        requestId, operationCode, returnData);
    if (dmDeviceAuthCallback_ == nullptr) {
        LOGE("HiChainAuthConnector::onFinish dmDeviceAuthCallback_ is nullptr.");
        return;
    }
    dmDeviceAuthCallback_->AuthDeviceFinish(requestId);
}

void HiChainAuthConnector::onError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
{
    LOGI("HichainAuthenCallBack::onError reqId:%lld, operation:%d, errorCode:%d.", requestId, operationCode, errorCode);
    (void)operationCode;
    (void)errorReturn;
    if (dmDeviceAuthCallback_ == nullptr) {
        LOGE("HiChainAuthConnector::onError dmDeviceAuthCallback_ is nullptr.");
        return;
    }
    dmDeviceAuthCallback_->AuthDeviceError(requestId, ERR_DM_FAILED);
}

void HiChainAuthConnector::onSessionKeyReturned(int64_t requestId, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    LOGI("HiChainAuthConnector::onSessionKeyReturned start.");
    if (dmDeviceAuthCallback_ == nullptr) {
        LOGE("HiChainAuthConnector::onSessionKeyReturned dmDeviceAuthCallback_ is nullptr.");
        return;
    }
    dmDeviceAuthCallback_->AuthDeviceSessionKey(requestId, sessionKey, sessionKeyLen);
}

int32_t HiChainAuthConnector::GenerateCredential(std::string &localUdid, int32_t osAccountId, std::string &publicKey)
{
    LOGI("HiChainAuthConnector::GenerateCredential start.");
    nlohmann::json jsonObj;
    jsonObj["osAccountId"] = osAccountId;
    jsonObj["deviceId"] = localUdid;
    jsonObj["acquireType"] = P2P_BIND;
    jsonObj["flag"] = 1;
    char *requestParam = strdup(jsonObj.dump().c_str());
    char *returnData = nullptr;
    if (ProcessCredential(CRED_OP_CREATE, requestParam, &returnData) != HC_SUCCESS) {
        LOGE("Hichain generate credential failed.");
        return ERR_DM_FAILED;
    }
    std::string returnDataStr = static_cast<std::string>(returnData);
    nlohmann::json jsonObject = nlohmann::json::parse(returnDataStr, nullptr, false);
    if (jsonObject.is_discarded()) {
        LOGE("Decode generate return data jsonStr error.");
        return ERR_DM_FAILED;
    }
    if (!IsInt32(jsonObject, "result") || !IsString(jsonObject, "publicKey") ||
        jsonObject["result"].get<int32_t>() != HC_SUCCESS) {
        LOGE("Hichain generate public key jsonObject invalied.");
        return ERR_DM_FAILED;
    }
    if (jsonObject["result"].get<int32_t>() != 0) {
        LOGE("Hichain generate public key failed");
        return ERR_DM_FAILED;
    }
    publicKey = jsonObject["publicKey"].get<std::string>();
    return DM_OK;
}

bool HiChainAuthConnector::QueryCredential(std::string &localUdid, int32_t osAccountId)
{
    LOGI("HiChainAuthConnector::QueryCredential start.");
    nlohmann::json jsonObj;
    jsonObj["osAccountId"] = osAccountId;
    jsonObj["deviceId"] = localUdid;
    jsonObj["acquireType"] = P2P_BIND;
    jsonObj["flag"] = 1;
    char *requestParam = strdup(jsonObj.dump().c_str());
    char *returnData = nullptr;
    if (ProcessCredential(CRED_OP_QUERY, requestParam, &returnData) != HC_SUCCESS) {
        LOGE("Hichain query credential failed.");
        return false;
    }
    std::string returnDataStr = static_cast<std::string>(returnData);
    nlohmann::json jsonObject = nlohmann::json::parse(returnDataStr, nullptr, false);
    if (jsonObject.is_discarded()) {
        LOGE("Decode query return data jsonStr error.");
        return false;
    }
    if (!IsInt32(jsonObject, "result") || jsonObject["result"].get<int32_t>() == -1) {
        LOGE("Hichain generate public key failed.");
        return false;
    }
    if (!IsString(jsonObject, "publicKey") || jsonObject["result"].get<int32_t>() == 1) {
        LOGI("Credential not exist.");
        return false;
    }
    return true;
}

int32_t HiChainAuthConnector::ImportCredential(int32_t osAccountId, std::string deviceId, std::string publicKey)
{
    LOGI("HiChainAuthConnector::ImportCredential");
    nlohmann::json jsonObj;
    jsonObj["osAccountId"] = osAccountId;
    jsonObj["deviceId"] = deviceId;
    jsonObj["acquireType"] = P2P_BIND;
    jsonObj["publicKey"] = publicKey;
    char *requestParam = strdup(jsonObj.dump().c_str());
    char *returnData = nullptr;
    if (ProcessCredential(CRED_OP_IMPORT, requestParam, &returnData) != HC_SUCCESS) {
        LOGE("Hichain query credential failed.");
        return ERR_DM_FAILED;
    }
    std::string returnDataStr = static_cast<std::string>(returnData);
    nlohmann::json jsonObject = nlohmann::json::parse(returnDataStr, nullptr, false);
    if (jsonObject.is_discarded()) {
        LOGE("Decode import return data jsonStr error.");
        return ERR_DM_FAILED;
    }
    if (!IsInt32(jsonObject, "result")) {
        LOGI("Hichain import public key jsonObject invalied.", jsonObject["result"].get<int32_t>());
        return ERR_DM_FAILED;
    }
    int32_t result = jsonObject["result"].get<int32_t>();
    if (result != 0) {
        LOGE("Hichain import public key result is %d.", result);
        return ERR_DM_FAILED;
    }
    return DM_OK;
}

int32_t HiChainAuthConnector::DeleteCredential(const std::string &deviceId, int32_t userId)
{
    LOGI("DeleteCredential start.");
    nlohmann::json jsonObj;
    jsonObj["deviceId"] = deviceId;
    jsonObj["acquireType"] = P2P_BIND;
    jsonObj["osAccountId"] = userId;
    char *requestParam = strdup(jsonObj.dump().c_str());
    char *returnData = nullptr;
    if (ProcessCredential(CRED_OP_DELETE, requestParam, &returnData) != HC_SUCCESS) {
        LOGE("Hichain query credential failed.");
        return false;
    }
    std::string returnDataStr = static_cast<std::string>(returnData);
    nlohmann::json jsonObject = nlohmann::json::parse(returnDataStr, nullptr, false);
    if (jsonObject.is_discarded()) {
        LOGE("Decode import return data jsonStr error.");
        return false;
    }
    if (!IsInt32(jsonObject, "result")) {
        LOGI("Hichain delete credential result json key is invalied.");
        return ERR_DM_FAILED;
    }
    return jsonObject["result"].get<int32_t>();
}
} // namespace DistributedHardware
} // namespace OHOS