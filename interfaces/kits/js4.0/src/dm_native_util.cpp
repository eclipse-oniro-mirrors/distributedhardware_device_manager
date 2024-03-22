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

#include "dm_native_util.h"

#include "dm_anonymous.h"
#include "dm_constants.h"
#include "dm_log.h"
#include "ipc_skeleton.h"
#include "js_native_api.h"
#include "tokenid_kit.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace DistributedHardware {
namespace {
const std::string ERR_MESSAGE_NO_PERMISSION = "Permission verify failed.";
const std::string ERR_MESSAGE_NOT_SYSTEM_APP = "The caller is not a system application.";
const std::string ERR_MESSAGE_INVALID_PARAMS = "Input parameter error.";
const std::string ERR_MESSAGE_FAILED = "Failed to execute the function.";
const std::string ERR_MESSAGE_OBTAIN_SERVICE = "Failed to obtain the service.";
const std::string ERR_MESSAGE_AUTHENTICALTION_INVALID = "Authentication invalid.";
const std::string ERR_MESSAGE_DISCOVERY_INVALID = "Discovery invalid.";
const std::string ERR_MESSAGE_PUBLISH_INVALID = "Publish invalid.";

const int32_t DM_NAPI_DISCOVER_EXTRA_INIT_ONE = -1;
const int32_t DM_NAPI_DISCOVER_EXTRA_INIT_TWO = -2;
const int32_t DM_NAPI_DESCRIPTION_BUF_LENGTH = 16384;
const int32_t DM_NAPI_BUF_LENGTH = 256;

void JsObjectToString(const napi_env &env, const napi_value &object, const std::string &fieldStr,
                      char *dest, const int32_t destLen)
{
    bool hasProperty = false;
    NAPI_CALL_RETURN_VOID(env, napi_has_named_property(env, object, fieldStr.c_str(), &hasProperty));
    if (hasProperty) {
        napi_value field = nullptr;
        napi_valuetype valueType = napi_undefined;

        napi_get_named_property(env, object, fieldStr.c_str(), &field);
        NAPI_CALL_RETURN_VOID(env, napi_typeof(env, field, &valueType));
        if (!CheckArgsType(env, valueType == napi_string, fieldStr.c_str(), "string")) {
            return;
        }
        size_t result = 0;
        NAPI_CALL_RETURN_VOID(env, napi_get_value_string_utf8(env, field, dest, destLen, &result));
    } else {
        LOGE("devicemanager napi js to str no property: %{public}s", fieldStr.c_str());
    }
}

void JsObjectToBool(const napi_env &env, const napi_value &object, const std::string &fieldStr,
                    bool &fieldRef)
{
    bool hasProperty = false;
    NAPI_CALL_RETURN_VOID(env, napi_has_named_property(env, object, fieldStr.c_str(), &hasProperty));
    if (hasProperty) {
        napi_value field = nullptr;
        napi_valuetype valueType = napi_undefined;

        napi_get_named_property(env, object, fieldStr.c_str(), &field);
        NAPI_CALL_RETURN_VOID(env, napi_typeof(env, field, &valueType));
        if (!CheckArgsType(env, valueType == napi_boolean, fieldStr.c_str(), "bool")) {
            return;
        }
        napi_get_value_bool(env, field, &fieldRef);
    } else {
        LOGE("devicemanager napi js to bool no property: %{public}s", fieldStr.c_str());
    }
}

void JsObjectToInt(const napi_env &env, const napi_value &object, const std::string &fieldStr,
                   int32_t &fieldRef)
{
    bool hasProperty = false;
    NAPI_CALL_RETURN_VOID(env, napi_has_named_property(env, object, fieldStr.c_str(), &hasProperty));
    if (hasProperty) {
        napi_value field = nullptr;
        napi_valuetype valueType = napi_undefined;

        napi_get_named_property(env, object, fieldStr.c_str(), &field);
        NAPI_CALL_RETURN_VOID(env, napi_typeof(env, field, &valueType));
        if (!CheckArgsType(env, valueType == napi_number, fieldStr.c_str(), "number")) {
            return;
        }
        napi_get_value_int32(env, field, &fieldRef);
    } else {
        LOGE("devicemanager napi js to int no property: %{public}s", fieldStr.c_str());
    }
}

std::string GetDeviceTypeById(DmDeviceType type)
{
    const static std::pair<DmDeviceType, std::string> mapArray[] = {
        {DEVICE_TYPE_UNKNOWN, DEVICE_TYPE_UNKNOWN_STRING},
        {DEVICE_TYPE_PHONE, DEVICE_TYPE_PHONE_STRING},
        {DEVICE_TYPE_PAD, DEVICE_TYPE_PAD_STRING},
        {DEVICE_TYPE_TV, DEVICE_TYPE_TV_STRING},
        {DEVICE_TYPE_CAR, DEVICE_TYPE_CAR_STRING},
        {DEVICE_TYPE_WATCH, DEVICE_TYPE_WATCH_STRING},
        {DEVICE_TYPE_WIFI_CAMERA, DEVICE_TYPE_WIFICAMERA_STRING},
        {DEVICE_TYPE_PC, DEVICE_TYPE_PC_STRING},
        {DEVICE_TYPE_SMART_DISPLAY, DEVICE_TYPE_SMART_DISPLAY_STRING},
        {DEVICE_TYPE_2IN1, DEVICE_TYPE_2IN1_STRING},
    };
    for (const auto& item : mapArray) {
        if (item.first == type) {
            return item.second;
        }
    }
    return DEVICE_TYPE_UNKNOWN_STRING;
}

bool CheckArgsVal(napi_env env, bool assertion, const std::string &param, const std::string &msg)
{
    if (!(assertion)) {
        std::string errMsg = ERR_MESSAGE_INVALID_PARAMS + "The value of " + param + ": " + msg;
        napi_throw_error(env, std::to_string(ERR_INVALID_PARAMS).c_str(), errMsg.c_str());
        return false;
    }
    return true;
}
}

napi_value GenerateBusinessError(napi_env env, int32_t err, const std::string &msg)
{
    napi_value businessError = nullptr;
    NAPI_CALL(env, napi_create_object(env, &businessError));
    napi_value errorCode = nullptr;
    NAPI_CALL(env, napi_create_int32(env, err, &errorCode));
    napi_value errorMessage = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, msg.c_str(), NAPI_AUTO_LENGTH, &errorMessage));
    NAPI_CALL(env, napi_set_named_property(env, businessError, "code", errorCode));
    NAPI_CALL(env, napi_set_named_property(env, businessError, "message", errorMessage));

    return businessError;
}

bool CheckArgsCount(napi_env env, bool assertion, const std::string &message)
{
    if (!(assertion)) {
        std::string errMsg = ERR_MESSAGE_INVALID_PARAMS + message;
        napi_throw_error(env, std::to_string(ERR_INVALID_PARAMS).c_str(), errMsg.c_str());
        return false;
    }
    return true;
}

bool CheckArgsType(napi_env env, bool assertion, const std::string &paramName, const std::string &type)
{
    if (!(assertion)) {
        std::string errMsg = ERR_MESSAGE_INVALID_PARAMS + "The type of " + paramName +
                " must be " + type;
        napi_throw_error(env, std::to_string(ERR_INVALID_PARAMS).c_str(), errMsg.c_str());
        return false;
    }
    return true;
}

napi_value CreateErrorForCall(napi_env env, int32_t code, const std::string &errMsg, bool isAsync)
{
    LOGI("CreateErrorForCall code:%{public}d, message:%{public}s", code, errMsg.c_str());
    napi_value error = nullptr;
    if (isAsync) {
        napi_throw_error(env, std::to_string(code).c_str(), errMsg.c_str());
    } else {
        error = GenerateBusinessError(env, code, errMsg);
    }
    return error;
}

napi_value CreateBusinessError(napi_env env, int32_t errCode, bool isAsync)
{
    napi_value error = nullptr;
    switch (errCode) {
        case ERR_DM_NO_PERMISSION:
            error = CreateErrorForCall(env, ERR_NO_PERMISSION, ERR_MESSAGE_NO_PERMISSION, isAsync);
            break;
        case ERR_DM_DISCOVERY_REPEATED:
            error = CreateErrorForCall(env, DM_ERR_DISCOVERY_INVALID, ERR_MESSAGE_DISCOVERY_INVALID, isAsync);
            break;
        case ERR_DM_PUBLISH_REPEATED:
            error = CreateErrorForCall(env, DM_ERR_PUBLISH_INVALID, ERR_MESSAGE_PUBLISH_INVALID, isAsync);
            break;
        case ERR_DM_AUTH_BUSINESS_BUSY:
            error = CreateErrorForCall(env, DM_ERR_AUTHENTICALTION_INVALID,
                ERR_MESSAGE_AUTHENTICALTION_INVALID, isAsync);
            break;
        case ERR_DM_INPUT_PARA_INVALID:
        case ERR_DM_UNSUPPORTED_AUTH_TYPE:
            error = CreateErrorForCall(env, ERR_INVALID_PARAMS, ERR_MESSAGE_INVALID_PARAMS, isAsync);
            break;
        case ERR_DM_INIT_FAILED:
            error = CreateErrorForCall(env, DM_ERR_OBTAIN_SERVICE, ERR_MESSAGE_OBTAIN_SERVICE, isAsync);
            break;
        case ERR_NOT_SYSTEM_APP:
            error = CreateErrorForCall(env, ERR_NOT_SYSTEM_APP, ERR_MESSAGE_NOT_SYSTEM_APP, isAsync);
            break;
        default:
            error = CreateErrorForCall(env, DM_ERR_FAILED, ERR_MESSAGE_FAILED, isAsync);
            break;
    }
    return error;
}

bool IsFunctionType(napi_env env, napi_value value)
{
    napi_valuetype eventHandleType = napi_undefined;
    napi_typeof(env, value, &eventHandleType);
    return CheckArgsType(env, eventHandleType == napi_function, "callback", "function");
}

void SetValueUtf8String(const napi_env &env, const std::string &fieldStr, const std::string &str,
                        napi_value &result)
{
    napi_value value = nullptr;
    napi_create_string_utf8(env, str.c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, fieldStr.c_str(), value);
}

void SetValueInt32(const napi_env &env, const std::string &fieldStr, const int32_t intValue,
                   napi_value &result)
{
    napi_value value = nullptr;
    napi_create_int32(env, intValue, &value);
    napi_set_named_property(env, result, fieldStr.c_str(), value);
}

void DeviceBasicInfoToJsArray(const napi_env &env,
                              const std::vector<DmDeviceBasicInfo> &vecDevInfo, const int32_t idx,
                              napi_value &arrayResult)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);
    DmDeviceBasicToJsObject(env, vecDevInfo[idx], result);

    napi_status status = napi_set_element(env, arrayResult, idx, result);
    if (status != napi_ok) {
        LOGE("DmDeviceBasicInfo To JsArray set element error: %{public}d", status);
    }
}

void DmDeviceBasicToJsObject(napi_env env, const DmDeviceBasicInfo &devInfo, napi_value &result)
{
    SetValueUtf8String(env, "deviceId", devInfo.deviceId, result);
    SetValueUtf8String(env, "networkId", devInfo.networkId, result);
    SetValueUtf8String(env, "deviceName", devInfo.deviceName, result);
    std::string deviceType = GetDeviceTypeById(static_cast<DmDeviceType>(devInfo.deviceTypeId));
    SetValueUtf8String(env, "deviceType", deviceType.c_str(), result);
}

void JsToDmPublishInfo(const napi_env &env, const napi_value &object, DmPublishInfo &info)
{
    int32_t publishId = -1;
    JsObjectToInt(env, object, "publishId", publishId);
    info.publishId = publishId;

    int32_t mode = -1;
    JsObjectToInt(env, object, "mode", mode);
    info.mode = static_cast<DmDiscoverMode>(mode);

    int32_t freq = -1;
    JsObjectToInt(env, object, "freq", freq);
    info.freq = static_cast<DmExchangeFreq>(freq);

    JsObjectToBool(env, object, "ranging", info.ranging);
    return;
}

void JsToBindParam(const napi_env &env, const napi_value &object, std::string &bindParam,
                   int32_t &bindType, bool &isMetaType)
{
    int32_t bindTypeTemp = -1;
    JsObjectToInt(env, object, "bindType", bindTypeTemp);
    bindType = bindTypeTemp;

    char appOperation[DM_NAPI_DESCRIPTION_BUF_LENGTH] = "";
    JsObjectToString(env, object, "appOperation", appOperation, sizeof(appOperation));
    char customDescription[DM_NAPI_DESCRIPTION_BUF_LENGTH] = "";
    JsObjectToString(env, object, "customDescription", customDescription, sizeof(customDescription));
    char targetPkgName[DM_NAPI_BUF_LENGTH] = "";
    JsObjectToString(env, object, "targetPkgName", targetPkgName, sizeof(targetPkgName));
    char metaType[DM_NAPI_BUF_LENGTH] = "";
    JsObjectToString(env, object, "metaType", metaType, sizeof(metaType));
    std::string metaTypeStr = metaType;
    isMetaType = !metaTypeStr.empty();

    char pinCode[DM_NAPI_BUF_LENGTH] = "";
    JsObjectToString(env, object, "pinCode", pinCode, sizeof(pinCode));
    char authToken[DM_NAPI_BUF_LENGTH] = "";
    JsObjectToString(env, object, "authToken", authToken, sizeof(authToken));
    char brMac[DM_NAPI_BUF_LENGTH] = "";
    JsObjectToString(env, object, "brMac", brMac, sizeof(brMac));
    char bleMac[DM_NAPI_BUF_LENGTH] = "";
    JsObjectToString(env, object, "bleMac", bleMac, sizeof(bleMac));
    char wifiIP[DM_NAPI_BUF_LENGTH] = "";
    JsObjectToString(env, object, "wifiIP", wifiIP, sizeof(wifiIP));

    int32_t wifiPort = -1;
    JsObjectToInt(env, object, "wifiPort", wifiPort);
    int32_t bindLevel = 0;
    JsObjectToInt(env, object, "bindLevel", bindLevel);

    nlohmann::json jsonObj;
    jsonObj[AUTH_TYPE] = bindType;
    jsonObj[APP_OPERATION] = std::string(appOperation);
    jsonObj[CUSTOM_DESCRIPTION] = std::string(customDescription);
    jsonObj[PARAM_KEY_TARGET_PKG_NAME] = std::string(targetPkgName);
    jsonObj[PARAM_KEY_META_TYPE] = metaTypeStr;
    jsonObj[PARAM_KEY_PIN_CODE] = std::string(pinCode);
    jsonObj[PARAM_KEY_AUTH_TOKEN] = std::string(authToken);
    jsonObj[PARAM_KEY_BR_MAC] = std::string(brMac);
    jsonObj[PARAM_KEY_BLE_MAC] = std::string(bleMac);
    jsonObj[PARAM_KEY_WIFI_IP] = std::string(wifiIP);
    jsonObj[PARAM_KEY_WIFI_PORT] = wifiPort;
    jsonObj[BIND_LEVEL] = bindLevel;
    jsonObj[TOKENID] = OHOS::IPCSkeleton::GetSelfTokenID();
    bindParam = jsonObj.dump();
}

bool IsSystemApp()
{
    uint64_t tokenId = OHOS::IPCSkeleton::GetSelfTokenID();
    return OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId);
}

bool JsToDiscoverTargetType(napi_env env, const napi_value &object, int32_t &discoverTargetType)
{
    napi_valuetype objectType = napi_undefined;
    napi_typeof(env, object, &objectType);
    if (!(CheckArgsType(env, objectType == napi_object, "discoverParameter", "object or undefined"))) {
        return false;
    }
    bool hasProperty = false;
    napi_has_named_property(env, object, "discoverTargetType", &hasProperty);
    if (hasProperty) {
        napi_value field = nullptr;
        napi_valuetype valueType = napi_undefined;
        napi_get_named_property(env, object, "discoverTargetType", &field);
        napi_typeof(env, field, &valueType);
        if (!CheckArgsType(env, valueType == napi_number, "discoverTargetType", "number")) {
            return false;
        }
        napi_get_value_int32(env, field, &discoverTargetType);
        return true;
    }
    LOGE("discoverTargetType is invalid.");
    return false;
}

void JsToDmDiscoveryExtra(const napi_env &env, const napi_value &object, std::string &extra)
{
    nlohmann::json jsonObj;
    int32_t availableStatus = DM_NAPI_DISCOVER_EXTRA_INIT_ONE;
    JsObjectToInt(env, object, "availableStatus", availableStatus);
    if (availableStatus != DM_NAPI_DISCOVER_EXTRA_INIT_ONE) {
        jsonObj["credible"] = availableStatus;
    }

    int32_t discoverDistance = DM_NAPI_DISCOVER_EXTRA_INIT_ONE;
    JsObjectToInt(env, object, "discoverDistance", discoverDistance);
    if (discoverDistance != DM_NAPI_DISCOVER_EXTRA_INIT_ONE) {
        jsonObj["range"] = discoverDistance;
    }

    int32_t authenticationStatus = DM_NAPI_DISCOVER_EXTRA_INIT_ONE;
    JsObjectToInt(env, object, "authenticationStatus", authenticationStatus);
    if (authenticationStatus != DM_NAPI_DISCOVER_EXTRA_INIT_ONE) {
        jsonObj["isTrusted"] = authenticationStatus;
    }

    int32_t authorizationType = DM_NAPI_DISCOVER_EXTRA_INIT_TWO;
    JsObjectToInt(env, object, "authorizationType", authorizationType);
    if (authorizationType != DM_NAPI_DISCOVER_EXTRA_INIT_TWO) {
        jsonObj["authForm"] = authorizationType;
    }

    int32_t deviceType = DM_NAPI_DISCOVER_EXTRA_INIT_ONE;
    JsObjectToInt(env, object, "deviceType", deviceType);
    if (deviceType != DM_NAPI_DISCOVER_EXTRA_INIT_ONE) {
        jsonObj["deviceType"] = deviceType;
    }
    extra = jsonObj.dump();
    LOGI("JsToDmDiscoveryExtra, extra :%{public}s", extra.c_str());
}

void InsertMapParames(nlohmann::json &bindParamObj, std::map<std::string, std::string> &bindParamMap)
{
    LOGI("Insert map parames start");
    if (IsInt32(bindParamObj, AUTH_TYPE)) {
        int32_t authType = bindParamObj[AUTH_TYPE].get<int32_t>();
        bindParamMap.insert(std::pair<std::string, std::string>(PARAM_KEY_AUTH_TYPE, std::to_string(authType)));
    }
    if (IsString(bindParamObj, APP_OPERATION)) {
        std::string appOperation = bindParamObj[APP_OPERATION].get<std::string>();
        bindParamMap.insert(std::pair<std::string, std::string>(PARAM_KEY_APP_OPER, appOperation));
    }
    if (IsString(bindParamObj, CUSTOM_DESCRIPTION)) {
        std::string appDescription = bindParamObj[CUSTOM_DESCRIPTION].get<std::string>();
        bindParamMap.insert(std::pair<std::string, std::string>(PARAM_KEY_APP_DESC, appDescription));
    }
    if (IsString(bindParamObj, PARAM_KEY_TARGET_PKG_NAME)) {
        std::string targetPkgName = bindParamObj[PARAM_KEY_TARGET_PKG_NAME].get<std::string>();
        bindParamMap.insert(std::pair<std::string, std::string>(PARAM_KEY_TARGET_PKG_NAME, targetPkgName));
    }
    if (IsString(bindParamObj, PARAM_KEY_META_TYPE)) {
        std::string metaType = bindParamObj[PARAM_KEY_META_TYPE].get<std::string>();
        bindParamMap.insert(std::pair<std::string, std::string>(PARAM_KEY_META_TYPE, metaType));
    }
    if (IsString(bindParamObj, PARAM_KEY_PIN_CODE)) {
        std::string pinCode = bindParamObj[PARAM_KEY_PIN_CODE].get<std::string>();
        bindParamMap.insert(std::pair<std::string, std::string>(PARAM_KEY_PIN_CODE, pinCode));
    }
    if (IsString(bindParamObj, PARAM_KEY_AUTH_TOKEN)) {
        std::string authToken = bindParamObj[PARAM_KEY_AUTH_TOKEN].get<std::string>();
        bindParamMap.insert(std::pair<std::string, std::string>(PARAM_KEY_AUTH_TOKEN, authToken));
    }
}

bool JsToStringAndCheck(napi_env env, napi_value value, const std::string &valueName, std::string &strValue)
{
    napi_valuetype deviceIdType = napi_undefined;
    napi_typeof(env, value, &deviceIdType);
    if (!CheckArgsType(env, deviceIdType == napi_string, valueName, "string")) {
        return false;
    }
    size_t valueLen = 0;
    napi_get_value_string_utf8(env, value, nullptr, 0, &valueLen);
    if (!CheckArgsVal(env, valueLen > 0, valueName, "len == 0")) {
        return false;
    }
    if (!CheckArgsVal(env, valueLen < DM_NAPI_BUF_LENGTH, valueName, "len >= MAXLEN")) {
        return false;
    }
    char temp[DM_NAPI_BUF_LENGTH] = {0};
    napi_get_value_string_utf8(env, value, temp, valueLen + 1, &valueLen);
    strValue = temp;
    return true;
}
} // namespace DistributedHardware
} // namespace OHOS
