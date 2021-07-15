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

#include "native_devicemanager_js.h"

#include <securec.h>

#include "device_manager.h"
#include "device_manager_log.h"

using namespace OHOS::DistributedHardware;

namespace {
#define GET_PARAMS(env, info, num)      \
    size_t argc = num;                  \
    napi_value argv[num] = { nullptr }; \
    napi_value thisVar = nullptr;       \
    void *data = nullptr;               \
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data))

const std::string DM_NAPI_EVENT_DEVICE_STATE_CHANGE = "deviceStateChange";
const std::string DM_NAPI_EVENT_DEVICE_FOUND = "deviceFound";
const std::string DM_NAPI_EVENT_DEVICE_DISCOVER_FAIL = "discoverFail";
const std::string DM_NAPI_EVENT_DEVICE_AUTH_RESULT = "authResult";
const std::string DM_NAPI_EVENT_DEVICE_SERVICE_DIE = "serviceDie";

const std::string DEVICE_MANAGER_NAPI_CLASS_NAME = "DeviceManager";

const int DM_NAPI_ARGS_ONE = 1;
const int DM_NAPI_ARGS_TWO = 2;
const int DM_NAPI_SUB_ID_MAX = 65535;

std::map<std::string, DeviceManagerNapi *> g_deviceManagerMap;
std::map<std::string, std::shared_ptr<DmNapiInitCallback>> g_initCallbackMap;
std::map<std::string, std::shared_ptr<DmNapiDeviceStateCallback>> g_deviceStateCallbackMap;
std::map<std::string, std::shared_ptr<DmNapiDiscoverCallback>> g_discoverCallbackMap;
std::map<std::string, std::shared_ptr<DmNapiAuthenticateCallback>> g_authCallbackMap;
}

enum DmNapiSubscribeCap {
    DM_NAPI_SUBSCRIBE_CAPABILITY_DDMP = 0
};

napi_ref DeviceManagerNapi::sConstructor_ = nullptr;

void DmNapiInitCallback::OnRemoteDied()
{
    DeviceManagerNapi *deviceManagerNapi = DeviceManagerNapi::GetDeviceManagerNapi(bundleName_);
    if (deviceManagerNapi == nullptr) {
        HILOGE("OnRemoteDied, deviceManagerNapi not find for bunderName %{public}s", bundleName_.c_str());
        return;
    }
    deviceManagerNapi->OnEvent("serviceDie", 0, nullptr);
}

void DmNapiDeviceStateCallback::OnDeviceOnline(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    DeviceManagerNapi *deviceManagerNapi = DeviceManagerNapi::GetDeviceManagerNapi(bundleName_);
    if (deviceManagerNapi == nullptr) {
        HILOGE("OnDeviceOnline, deviceManagerNapi not find for bunderName %{public}s", bundleName_.c_str());
        return;
    }
    deviceManagerNapi->OnDeviceStateChange(DmNapiDevStateChangeAction::ONLINE, deviceInfo);
}

void DmNapiDeviceStateCallback::OnDeviceReady(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    DeviceManagerNapi *deviceManagerNapi = DeviceManagerNapi::GetDeviceManagerNapi(bundleName_);
    if (deviceManagerNapi == nullptr) {
        HILOGE("OnDeviceOnline, deviceManagerNapi not find for bunderName %{public}s", bundleName_.c_str());
        return;
    }
    deviceManagerNapi->OnDeviceStateChange(DmNapiDevStateChangeAction::READY, deviceInfo);
}

void DmNapiDeviceStateCallback::OnDeviceOffline(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    DeviceManagerNapi *deviceManagerNapi = DeviceManagerNapi::GetDeviceManagerNapi(bundleName_);
    if (deviceManagerNapi == nullptr) {
        HILOGE("OnDeviceOffline, deviceManagerNapi not find for bunderName %{public}s", bundleName_.c_str());
        return;
    }
    deviceManagerNapi->OnDeviceStateChange(DmNapiDevStateChangeAction::OFFLINE, deviceInfo);
}

void DmNapiDeviceStateCallback::OnDeviceChanged(const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    DeviceManagerNapi *deviceManagerNapi = DeviceManagerNapi::GetDeviceManagerNapi(bundleName_);
    if (deviceManagerNapi == nullptr) {
        HILOGE("OnDeviceChanged, deviceManagerNapi not find for bunderName %{public}s", bundleName_.c_str());
        return;
    }
    deviceManagerNapi->OnDeviceStateChange(DmNapiDevStateChangeAction::CHANGE, deviceInfo);
}

void DmNapiDiscoverCallback::OnDeviceFound(uint16_t subscribeId,
    OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    DeviceManagerNapi *deviceManagerNapi = DeviceManagerNapi::GetDeviceManagerNapi(bundleName_);
    if (deviceManagerNapi == nullptr) {
        HILOGE("OnDeviceFound, deviceManagerNapi not find for bunderName %{public}s", bundleName_.c_str());
        return;
    }

    HILOGI("OnDeviceFound for %{public}s, subscribeId %{public}d", bundleName_.c_str(), (int32_t)subscribeId);
    deviceManagerNapi->OnDeviceFound(subscribeId, deviceInfo);
}

void DmNapiDiscoverCallback::OnDiscoverFailed(uint16_t subscribeId, int32_t failedReason)
{
    DeviceManagerNapi *deviceManagerNapi = DeviceManagerNapi::GetDeviceManagerNapi(bundleName_);
    if (deviceManagerNapi == nullptr) {
        HILOGE("OnDiscoverFailed, deviceManagerNapi not find for bunderName %{public}s", bundleName_.c_str());
        return;
    }

    deviceManagerNapi->OnDiscoverFailed(subscribeId, failedReason);
}

void DmNapiDiscoverCallback::OnDiscoverySuccess(uint16_t subscribeId)
{
    DeviceManagerNapi *deviceManagerNapi = DeviceManagerNapi::GetDeviceManagerNapi(bundleName_);
    if (deviceManagerNapi == nullptr) {
        HILOGE("OnDiscoverySuccess, deviceManagerNapi not find for bunderName %{public}s", bundleName_.c_str());
        return;
    }
    HILOGE("DiscoverySuccess for %{public}s, subscribeId %{public}d", bundleName_.c_str(), (int32_t)subscribeId);
}

void DmNapiDiscoverCallback::IncreaseRefCount()
{
    refCount_++;
}

void DmNapiDiscoverCallback::DecreaseRefCount()
{
    refCount_--;
}

int32_t DmNapiDiscoverCallback::GetRefCount()
{
    return refCount_;
}

void DmNapiAuthenticateCallback::OnAuthResult(std::string &deviceId, int32_t status, int32_t reason)
{
    DeviceManagerNapi *deviceManagerNapi = DeviceManagerNapi::GetDeviceManagerNapi(bundleName_);
    if (deviceManagerNapi == nullptr) {
        HILOGE("OnAuthResult, deviceManagerNapi not find for bunderName %{public}s", bundleName_.c_str());
        return;
    }
    deviceManagerNapi->OnAuthResult(deviceId, status, reason);
}

DeviceManagerNapi::DeviceManagerNapi(napi_env env, napi_value thisVar) : DmNativeEvent(env, thisVar)
{
    env_ = env;
    wrapper_ = nullptr;
}

DeviceManagerNapi::~DeviceManagerNapi()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

DeviceManagerNapi *DeviceManagerNapi::GetDeviceManagerNapi(std::string &buldleName)
{
    auto iter = g_deviceManagerMap.find(buldleName);
    if (iter == g_deviceManagerMap.end()) {
        return nullptr;
    }
    return iter->second;
}

void DeviceManagerNapi::OnDeviceStateChange(DmNapiDevStateChangeAction action,
    const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    napi_value result;
    napi_create_object(env_, &result);
    SetValueInt32(env_, "action", (int)action, result);

    napi_value device;
    napi_create_object(env_, &device);
    SetValueUtf8String(env_, "deviceId", deviceInfo.deviceId, device);
    SetValueUtf8String(env_, "deviceName", deviceInfo.deviceName, device);
    SetValueInt32(env_, "deviceType", (int)deviceInfo.deviceTypeId, device);

    napi_set_named_property(env_, result, "device", device);
    OnEvent("deviceStateChange", DM_NAPI_ARGS_ONE, &result);
}

void DeviceManagerNapi::OnDeviceFound(uint16_t subscribeId, const OHOS::DistributedHardware::DmDeviceInfo &deviceInfo)
{
    HILOGI("OnDeviceFound for subscribeId %{public}d", (int32_t)subscribeId);
    napi_value result;
    napi_create_object(env_, &result);
    SetValueInt32(env_, "subscribeId", (int)subscribeId, result);

    napi_value device;
    napi_create_object(env_, &device);
    SetValueUtf8String(env_, "deviceId", deviceInfo.deviceId, device);
    SetValueUtf8String(env_, "deviceName", deviceInfo.deviceName, device);
    SetValueInt32(env_, "deviceType", (int)deviceInfo.deviceTypeId, device);

    napi_set_named_property(env_, result, "device", device);
    OnEvent("deviceFound", DM_NAPI_ARGS_ONE, &result);
}

void DeviceManagerNapi::OnDiscoverFailed(uint16_t subscribeId, int32_t failedReason)
{
    HILOGI("OnDiscoverFailed for subscribeId %{public}d", (int32_t)subscribeId);
    napi_value result;
    napi_create_object(env_, &result);
    SetValueInt32(env_, "subscribeId", (int)subscribeId, result);
    SetValueInt32(env_, "reason", (int)failedReason, result);
    OnEvent("discoverFail", DM_NAPI_ARGS_ONE, &result);
}

void DeviceManagerNapi::OnAuthResult(const std::string& deviceId, int32_t status, int32_t reason)
{
    HILOGI("OnAuthResult for status: %{public}d, reason: %{public}d", status, reason);
    napi_value result;
    napi_create_object(env_, &result);

    SetValueUtf8String(env_, "deviceId", deviceId, result);
    SetValueInt32(env_, "status", (int)status, result);
    SetValueInt32(env_, "reason", (int)reason, result);
    OnEvent("authResult", DM_NAPI_ARGS_ONE, &result);
}

void DeviceManagerNapi::SetValueUtf8String(const napi_env &env, const std::string& fieldStr, const std::string& str,
    napi_value& result)
{
    napi_value value;
    napi_create_string_utf8(env, str.c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, fieldStr.c_str(), value);
}

void DeviceManagerNapi::SetValueInt32(const napi_env& env, const std::string& fieldStr, const int intValue,
    napi_value& result)
{
    napi_value value;
    napi_create_int32(env, intValue, &value);
    napi_set_named_property(env, result, fieldStr.c_str(), value);
}

void DeviceManagerNapi::DeviceInfoToJsArray(const napi_env& env,
    const std::vector<OHOS::DistributedHardware::DmDeviceInfo>& vecDevInfo,
    const int idx, napi_value& arrayResult)
{
    napi_value result;
    napi_create_object(env, &result);

    SetValueUtf8String(env, "deviceId", vecDevInfo[idx].deviceId.c_str(), result);
    SetValueUtf8String(env, "deviceName", vecDevInfo[idx].deviceName.c_str(), result);
    SetValueInt32(env, "deviceType", (int)vecDevInfo[idx].deviceTypeId, result);

    napi_status status = napi_set_element(env, arrayResult, idx, result);
    if (status != napi_ok) {
        HILOGE("DmDeviceInfo To JsArray set element error: %{public}d", status);
    }
}

void DeviceManagerNapi::JsObjectToString(const napi_env& env, const napi_value& object,
    const std::string& fieldStr, const int bufLen, std::string& fieldRef)
{
    bool hasProperty = false;
    NAPI_CALL_RETURN_VOID(env, napi_has_named_property(env, object, fieldStr.c_str(), &hasProperty));
    if (hasProperty) {
        napi_value field;
        napi_valuetype valueType;

        napi_get_named_property(env, object, fieldStr.c_str(), &field);
        NAPI_CALL_RETURN_VOID(env, napi_typeof(env, field, &valueType));
        NAPI_ASSERT_RETURN_VOID(env, valueType == napi_string, "Wrong argument type. String expected.");
        if (bufLen <= 0) {
            HILOGE("js object to str bufLen invalid");
            return;
        }
        std::unique_ptr<char[]> buf = std::make_unique<char[]>(bufLen);
        if (buf == nullptr) {
            HILOGE("js object to str malloc failed");
            return;
        }
        (void)memset_s(buf.get(), bufLen, 0, bufLen);
        size_t result = 0;
        NAPI_CALL_RETURN_VOID(env, napi_get_value_string_utf8(env, field, buf.get(), bufLen, &result));
        fieldRef = buf.get();
    } else {
        HILOGE("devicemanager napi js to str no property: %{public}s", fieldStr.c_str());
    }
}

void DeviceManagerNapi::JsObjectToInt(const napi_env& env, const napi_value& object,
    const std::string& fieldStr, int& fieldRef)
{
    bool hasProperty = false;
    NAPI_CALL_RETURN_VOID(env, napi_has_named_property(env, object, fieldStr.c_str(), &hasProperty));
    if (hasProperty) {
        napi_value field;
        napi_valuetype valueType;

        napi_get_named_property(env, object, fieldStr.c_str(), &field);
        NAPI_CALL_RETURN_VOID(env, napi_typeof(env, field, &valueType));
        NAPI_ASSERT_RETURN_VOID(env, valueType == napi_number, "Wrong argument type. Number expected.");
        napi_get_value_int32(env, field, &fieldRef);
    } else {
        HILOGE("devicemanager napi js to int no property: %{public}s", fieldStr.c_str());
    }
}

void DeviceManagerNapi::JsObjectToBool(const napi_env& env, const napi_value& object,
    const std::string& fieldStr, bool& fieldRef)
{
    bool hasProperty = false;
    NAPI_CALL_RETURN_VOID(env, napi_has_named_property(env, object, fieldStr.c_str(), &hasProperty));
    if (hasProperty) {
        napi_value field;
        napi_valuetype valueType;

        napi_get_named_property(env, object, fieldStr.c_str(), &field);
        NAPI_CALL_RETURN_VOID(env, napi_typeof(env, field, &valueType));
        NAPI_ASSERT_RETURN_VOID(env, valueType == napi_boolean, "Wrong argument type. Bool expected.");
        napi_get_value_bool(env, field, &fieldRef);
    } else {
        HILOGE("devicemanager napi js to bool no property: %{public}s", fieldStr.c_str());
    }
}

int32_t DeviceManagerNapi::JsToDmSubscribeInfo(const napi_env& env, const napi_value& object,
    OHOS::DistributedHardware::DmSubscribeInfo& info)
{
    int subscribeId = -1;
    JsObjectToInt(env, object, "subscribeId", subscribeId);
    if (subscribeId < 0 || subscribeId > DM_NAPI_SUB_ID_MAX) {
        HILOGE("DeviceManagerNapi::JsToDmSubscribeInfo, subscribeId error, subscribeId: %{public}d ", subscribeId);
        return -1;
    }

    info.subscribeId = (uint16_t)subscribeId;

    int mode = -1;
    JsObjectToInt(env, object, "mode", mode);
    info.mode = (DmDiscoverMode)mode;

    int medium = -1;
    JsObjectToInt(env, object, "medium", medium);
    info.medium = (DmExchangeMedium)medium;

    int freq = -1;
    JsObjectToInt(env, object, "freq", freq);
    info.freq = (DmExchangeFreq)freq;

    JsObjectToBool(env, object, "isSameAccount", info.isSameAccount);
    JsObjectToBool(env, object, "isWakeRemote", info.isWakeRemote);

    int capability = -1;
    JsObjectToInt(env, object, "capability", capability);
    if (capability == DmNapiSubscribeCap::DM_NAPI_SUBSCRIBE_CAPABILITY_DDMP) {
        info.capability = std::string(DM_CAPABILITY_DDMP);
    }
    return 0;
}

void DeviceManagerNapi::JsToDmDeviceInfo(const napi_env& env, const napi_value& object,
    OHOS::DistributedHardware::DmDeviceInfo& info)
{
    JsObjectToString(env, object, "deviceId", DM_NAPI_BUF_LENGTH, info.deviceId);
    JsObjectToString(env, object, "deviceName", DM_NAPI_BUF_LENGTH, info.deviceName);
    int deviceType = -1;
    JsObjectToInt(env, object, "deviceType", deviceType);
    info.deviceTypeId = (DMDeviceType)deviceType;
}


void DeviceManagerNapi::CreateDmCallback(std::string &bundleName, std::string &eventType)
{
    HILOGE("CreateDmCallback for bunderName %{public}s eventType %{public}s", bundleName.c_str(), eventType.c_str());
    if (eventType == DM_NAPI_EVENT_DEVICE_STATE_CHANGE) {
        auto iter = g_deviceStateCallbackMap.find(bundleName);
        if (iter == g_deviceStateCallbackMap.end()) {
            auto callback = std::make_shared<DmNapiDeviceStateCallback>(bundleName);
            std::string extra = "";
            int32_t ret = DeviceManager::GetInstance().RegisterDevStateCallback(bundleName, extra, callback);
            if (ret != 0) {
                HILOGE("RegisterDevStateCallback failed for bunderName %{public}s", bundleName.c_str());
                return;
            }
            g_deviceStateCallbackMap[bundleName] = callback;
        }
        return;
    }

    if (eventType == DM_NAPI_EVENT_DEVICE_FOUND || eventType == DM_NAPI_EVENT_DEVICE_DISCOVER_FAIL) {
        std::shared_ptr<DmNapiDiscoverCallback> discoverCallback = nullptr;
        auto iter = g_discoverCallbackMap.find(bundleName);
        if (iter == g_discoverCallbackMap.end()) {
            auto callback = std::make_shared<DmNapiDiscoverCallback>(bundleName);
            g_discoverCallbackMap[bundleName] = callback;
            discoverCallback = callback;
        } else {
            discoverCallback = iter->second;
        }

        discoverCallback->IncreaseRefCount();
        return;
    }

    if (eventType == DM_NAPI_EVENT_DEVICE_AUTH_RESULT) {
        auto iter = g_authCallbackMap.find(bundleName);
        if (iter == g_authCallbackMap.end()) {
            auto callback = std::make_shared<DmNapiAuthenticateCallback>(bundleName);
            g_authCallbackMap[bundleName] = callback;
        }
        return;
    }
}

void DeviceManagerNapi::ReleaseDmCallback(std::string &bundleName, std::string &eventType)
{
    if (eventType == DM_NAPI_EVENT_DEVICE_STATE_CHANGE) {
        auto iter = g_deviceStateCallbackMap.find(bundleName);
        if (iter == g_deviceStateCallbackMap.end()) {
            HILOGE("ReleaseDmCallback: cannot find stateCallback for bunderName %{public}s", bundleName.c_str());
            return;
        }
        int32_t ret = DeviceManager::GetInstance().UnRegisterDevStateCallback(bundleName);
        if (ret != 0) {
            HILOGE("RegisterDevStateCallback failed for bunderName %{public}s", bundleName.c_str());
            return;
        }
        g_deviceStateCallbackMap.erase(bundleName);
        return;
    }

    if (eventType == DM_NAPI_EVENT_DEVICE_FOUND || eventType == DM_NAPI_EVENT_DEVICE_DISCOVER_FAIL) {
        std::shared_ptr<DmNapiDiscoverCallback> discoverCallback = nullptr;
        auto iter = g_discoverCallbackMap.find(bundleName);
        if (iter == g_discoverCallbackMap.end()) {
            return;
        }

        discoverCallback = iter->second;
        discoverCallback->DecreaseRefCount();
        if (discoverCallback->GetRefCount() == 0) {
            g_discoverCallbackMap.erase(bundleName);
        }
        return;
    }

    if (eventType == DM_NAPI_EVENT_DEVICE_AUTH_RESULT) {
        auto iter = g_authCallbackMap.find(bundleName);
        if (iter == g_authCallbackMap.end()) {
            return;
        }

        g_authCallbackMap.erase(bundleName);
    }
}

napi_value DeviceManagerNapi::GetTrustedDeviceListSync(napi_env env, napi_callback_info info)
{
    HILOGI("GetTrustedDeviceList in");
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_value array = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr));
    NAPI_ASSERT(env, argc == 0, "Wrong number of arguments");

    DeviceManagerNapi *deviceManagerWrapper = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&deviceManagerWrapper));
    std::string extra = "";
    std::vector<DmDeviceInfo> devList;
    int32_t ret = DeviceManager::GetInstance().GetTrustedDeviceList(deviceManagerWrapper->bundleName_, extra, devList);
    if (ret != 0) {
        HILOGE("GetTrustedDeviceList for bunderName %{public}s failed, ret %{public}d",
            deviceManagerWrapper->bundleName_.c_str(), ret);
        return array;
    }

    if (devList.size() > 0) {
        bool isArray = false;
        napi_create_array(env, &array);
        napi_is_array(env, array, &isArray);
        if (isArray == false) {
            HILOGE("napi_create_array fail");
        }

        for (size_t i = 0; i != devList.size(); ++i) {
            DeviceInfoToJsArray(env, devList, i, array);
        }
    } else {
        HILOGE("devList is null");
    }

    return array;
}

napi_value DeviceManagerNapi::StartDeviceDiscoverSync(napi_env env, napi_callback_info info)
{
    HILOGI("StartDeviceDiscoverSync in");
    GET_PARAMS(env, info, DM_NAPI_ARGS_ONE);
    napi_value result = nullptr;
    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "Wrong argument type. Object expected.");

    DeviceManagerNapi *deviceManagerWrapper = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&deviceManagerWrapper));

    std::shared_ptr<DmNapiDiscoverCallback> discoverCallback = nullptr;
    auto iter = g_discoverCallbackMap.find(deviceManagerWrapper->bundleName_);
    if (iter == g_discoverCallbackMap.end()) {
        discoverCallback = std::make_shared<DmNapiDiscoverCallback>(deviceManagerWrapper->bundleName_);
        g_discoverCallbackMap[deviceManagerWrapper->bundleName_] = discoverCallback;
    } else {
        discoverCallback = iter->second;
    }
    DmSubscribeInfo subInfo;
    int32_t res = JsToDmSubscribeInfo(env, argv[0], subInfo);
    NAPI_ASSERT(env, res == 0, "Wrong subscribeId ");

    int32_t ret = DeviceManager::GetInstance().StartDeviceDiscovery(deviceManagerWrapper->bundleName_,
        subInfo, discoverCallback);
    if (ret != 0) {
        HILOGE("StartDeviceDiscovery for bunderName %{public}s failed, ret %{public}d",
            deviceManagerWrapper->bundleName_.c_str(), ret);
        return result;
    }

    napi_get_undefined(env, &result);
    return result;
}

napi_value DeviceManagerNapi::StopDeviceDiscoverSync(napi_env env, napi_callback_info info)
{
    HILOGI("StopDeviceDiscoverSync in");
    GET_PARAMS(env, info, DM_NAPI_ARGS_ONE);
    napi_value result = nullptr;
    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "Wrong argument type. Object expected.");

    int32_t subscribeId = 0;
    napi_get_value_int32(env, argv[0], &subscribeId);
    NAPI_ASSERT(env, subscribeId <= DM_NAPI_SUB_ID_MAX, "Wrong argument. subscribeId Too Big.");

    DeviceManagerNapi *deviceManagerWrapper = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&deviceManagerWrapper));
    int32_t ret = DeviceManager::GetInstance().StopDeviceDiscovery(deviceManagerWrapper->bundleName_,
        (int16_t)subscribeId);
    if (ret != 0) {
        HILOGE("StopDeviceDiscovery for bunderName %{public}s failed, ret %{public}d",
            deviceManagerWrapper->bundleName_.c_str(), ret);
        return result;
    }

    napi_get_undefined(env, &result);
    return result;
}

napi_value DeviceManagerNapi::AuthenticateDeviceSync(napi_env env, napi_callback_info info)
{
    HILOGI("AuthenticateDeviceSync in");
    GET_PARAMS(env, info, DM_NAPI_ARGS_ONE);
    napi_value result = nullptr;
    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "Wrong argument type. Object expected.");

    DeviceManagerNapi *deviceManagerWrapper = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&deviceManagerWrapper));

    std::shared_ptr<DmNapiAuthenticateCallback> authCallback = nullptr;
    auto iter = g_authCallbackMap.find(deviceManagerWrapper->bundleName_);
    if (iter == g_authCallbackMap.end()) {
        authCallback = std::make_shared<DmNapiAuthenticateCallback>(deviceManagerWrapper->bundleName_);
        g_authCallbackMap[deviceManagerWrapper->bundleName_] = authCallback;
    } else {
        authCallback = iter->second;
    }
    DmDeviceInfo deviceInfo;
    JsToDmDeviceInfo(env, argv[0], deviceInfo);

    std::string extra = "";
    int32_t ret = DeviceManager::GetInstance().AuthenticateDevice(deviceManagerWrapper->bundleName_, deviceInfo,
        extra, authCallback);
    if (ret != 0) {
        HILOGE("AuthenticateDevice for bunderName %{public}s failed, ret %{public}d",
            deviceManagerWrapper->bundleName_.c_str(), ret);
        return result;
    }

    napi_get_undefined(env, &result);
    return result;
}

napi_value DeviceManagerNapi::JsOn(napi_env env, napi_callback_info info)
{
    HILOGI("JsOn in");
    GET_PARAMS(env, info, DM_NAPI_ARGS_TWO);
    NAPI_ASSERT(env, argc >= DM_NAPI_ARGS_TWO, "Wrong number of arguments, required 2");

    napi_valuetype eventValueType = napi_undefined;
    napi_typeof(env, argv[0], &eventValueType);
    NAPI_ASSERT(env, eventValueType == napi_string, "type mismatch for parameter 1");

    napi_valuetype eventHandleType = napi_undefined;
    napi_typeof(env, argv[1], &eventHandleType);
    NAPI_ASSERT(env, eventHandleType == napi_function, "type mismatch for parameter 2");

    size_t typeLen = 0;
    napi_get_value_string_utf8(env, argv[0], nullptr, 0, &typeLen);

    NAPI_ASSERT(env, typeLen > 0, "typeLen == 0");
    std::unique_ptr<char[]> type = std::make_unique<char[]>(typeLen + 1);
    napi_get_value_string_utf8(env, argv[0], type.get(), typeLen + 1, &typeLen);

    std::string eventType = type.get();
    DeviceManagerNapi *deviceManagerWrapper = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&deviceManagerWrapper));

    HILOGI("JsOn for bunderName %{public}s, eventType %{public}s ", deviceManagerWrapper->bundleName_.c_str(),
        eventType.c_str());
    deviceManagerWrapper->On(eventType, argv[1]);
    CreateDmCallback(deviceManagerWrapper->bundleName_, eventType);

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value DeviceManagerNapi::JsOff(napi_env env, napi_callback_info info)
{
    HILOGI("JsOff in");
    GET_PARAMS(env, info, DM_NAPI_ARGS_TWO);
    size_t requireArgc = 1;
    NAPI_ASSERT(env, argc >= requireArgc, "Wrong number of arguments, required 1");

    napi_valuetype eventValueType = napi_undefined;
    napi_typeof(env, argv[0], &eventValueType);
    NAPI_ASSERT(env, eventValueType == napi_string, "type mismatch for parameter 1");

    if (argc > requireArgc) {
        napi_valuetype eventHandleType = napi_undefined;
        napi_typeof(env, argv[1], &eventHandleType);
        NAPI_ASSERT(env, eventValueType == napi_function, "type mismatch for parameter 2");
    }

    size_t typeLen = 0;
    napi_get_value_string_utf8(env, argv[0], nullptr, 0, &typeLen);

    NAPI_ASSERT(env, typeLen > 0, "typeLen == 0");
    std::unique_ptr<char[]> type = std::make_unique<char[]>(typeLen + 1);
    napi_get_value_string_utf8(env, argv[0], type.get(), typeLen + 1, &typeLen);

    std::string eventType = type.get();
    DeviceManagerNapi *deviceManagerWrapper = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&deviceManagerWrapper));

    HILOGI("JsOff for bunderName %{public}s, eventType %{public}s ", deviceManagerWrapper->bundleName_.c_str(),
        eventType.c_str());
    deviceManagerWrapper->Off(eventType);
    ReleaseDmCallback(deviceManagerWrapper->bundleName_, eventType);

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value DeviceManagerNapi::ReleaseDeviceManager(napi_env env, napi_callback_info info)
{
    HILOGI("ReleaseDeviceManager in");
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr));
    NAPI_ASSERT(env, argc == 0, "Wrong number of arguments");

    DeviceManagerNapi *deviceManagerWrapper = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&deviceManagerWrapper));
    HILOGI("ReleaseDeviceManager for bunderName %{public}s", deviceManagerWrapper->bundleName_.c_str());
    int32_t ret = DeviceManager::GetInstance().UnInitDeviceManager(deviceManagerWrapper->bundleName_);
    if (ret != 0) {
        HILOGE("ReleaseDeviceManager for bunderName %{public}s failed, ret %{public}d",
            deviceManagerWrapper->bundleName_.c_str(), ret);
        napi_create_uint32(env, ret, &result);
        return result;
    }

    g_deviceManagerMap.erase(deviceManagerWrapper->bundleName_);
    g_initCallbackMap.erase(deviceManagerWrapper->bundleName_);
    g_deviceStateCallbackMap.erase(deviceManagerWrapper->bundleName_);
    g_discoverCallbackMap.erase(deviceManagerWrapper->bundleName_);
    g_authCallbackMap.erase(deviceManagerWrapper->bundleName_);
    napi_get_undefined(env, &result);
    return result;
}

void DeviceManagerNapi::HandleCreateDmCallBack(const napi_env &env, AsyncCallbackInfo *asCallbackInfo)
{
    napi_value resourceName;
    napi_create_string_latin1(env, "createDeviceManagerCallback", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            (void)env;
            AsyncCallbackInfo *asCallbackInfo = (AsyncCallbackInfo *)data;
            std::string bundleName = std::string(asCallbackInfo->bundleName);
            std::shared_ptr<DmNapiInitCallback> initCallback = std::make_shared<DmNapiInitCallback>(bundleName);
            if (DeviceManager::GetInstance().InitDeviceManager(bundleName, initCallback) != 0) {
                HILOGE("InitDeviceManager for bunderName %{public}s failed", bundleName.c_str());
                return;
            }
            g_initCallbackMap[bundleName] = initCallback;
            asCallbackInfo->status = 0;
        },
        [](napi_env env, napi_status status, void *data) {
            (void)status;
            AsyncCallbackInfo *asCallbackInfo = (AsyncCallbackInfo *)data;
            napi_value result[DM_NAPI_ARGS_TWO] = { 0 };
            napi_value ctor;
            napi_value argv;
            napi_get_reference_value(env, sConstructor_, &ctor);
            napi_create_string_utf8(env, asCallbackInfo->bundleName, NAPI_AUTO_LENGTH, &argv);
            napi_status ret = napi_new_instance(env, ctor, DM_NAPI_ARGS_ONE, &argv, &result[1]);
            if (ret != napi_ok) {
                HILOGE("Create DeviceManagerNapi for bunderName %{public}s failed", asCallbackInfo->bundleName);
                asCallbackInfo->status = -1;
            }

            if (asCallbackInfo->status == 0) {
                HILOGI("InitDeviceManager for bunderName %{public}s success", asCallbackInfo->bundleName);
                napi_get_undefined(env, &result[0]);
                napi_value callback = nullptr;
                napi_value callResult = nullptr;
                napi_get_reference_value(env, asCallbackInfo->callback, &callback);
                napi_call_function(env, nullptr, callback, DM_NAPI_ARGS_TWO, &result[0], &callResult);
                napi_delete_reference(env, asCallbackInfo->callback);
            } else {
                HILOGI("InitDeviceManager for bunderName %{public}s failed", asCallbackInfo->bundleName);
                napi_value message = nullptr;
                napi_create_object(env, &result[0]);
                napi_create_int32(env, asCallbackInfo->status, &message);
                napi_set_named_property(env, result[0], "code", message);
                napi_get_undefined(env, &result[1]);
            }
            napi_delete_async_work(env, asCallbackInfo->asyncWork);
            delete asCallbackInfo;
        },
        (void *)asCallbackInfo,
        &asCallbackInfo->asyncWork);
    napi_queue_async_work(env, asCallbackInfo->asyncWork);
}

napi_value DeviceManagerNapi::CreateDeviceManager(napi_env env, napi_callback_info info)
{
    HILOGI("CreateDeviceManager in");
    GET_PARAMS(env, info, DM_NAPI_ARGS_TWO);
    NAPI_ASSERT(env, argc >= DM_NAPI_ARGS_TWO, "Wrong number of arguments, required 2");

    napi_valuetype bundleNameValueType = napi_undefined;
    napi_typeof(env, argv[0], &bundleNameValueType);
    NAPI_ASSERT(env, bundleNameValueType == napi_string, "type mismatch for parameter 0");

    napi_valuetype funcValueType = napi_undefined;
    napi_typeof(env, argv[1], &funcValueType);
    NAPI_ASSERT(env, funcValueType == napi_function, "type mismatch for parameter 1");

    auto *asCallbackInfo = new AsyncCallbackInfo();
    asCallbackInfo->env = env;
    napi_get_value_string_utf8(env, argv[0], asCallbackInfo->bundleName, DM_NAPI_BUF_LENGTH - 1,
        &asCallbackInfo->bundleNameLen);
    napi_create_reference(env, argv[1], 1, &asCallbackInfo->callback);

    HandleCreateDmCallBack(env, asCallbackInfo);

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value DeviceManagerNapi::Constructor(napi_env env, napi_callback_info info)
{
    HILOGI("DeviceManagerNapi Constructor in");
    GET_PARAMS(env, info, DM_NAPI_ARGS_ONE);
    NAPI_ASSERT(env, argc >= DM_NAPI_ARGS_ONE, "Wrong number of arguments, required 1");

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_string, "type mismatch for parameter 1");

    char bundleName[DM_NAPI_BUF_LENGTH] = { 0 };
    size_t typeLen = 0;
    napi_get_value_string_utf8(env, argv[0], bundleName, sizeof(bundleName), &typeLen);

    HILOGI("create DeviceManagerNapi for packageName:%{public}s", bundleName);
    DeviceManagerNapi *obj = new DeviceManagerNapi(env, thisVar);
    obj->bundleName_ = std::string(bundleName);
    g_deviceManagerMap[obj->bundleName_] = obj;
    napi_wrap(env, thisVar, reinterpret_cast<void *>(obj),
        [](napi_env env, void *data, void *hint) {
            (void)env;
            (void)hint;
            DeviceManagerNapi *deviceManager = (DeviceManagerNapi *)data;
            delete deviceManager;
        },
        nullptr, &(obj->wrapper_));
    return thisVar;
}

napi_value DeviceManagerNapi::Init(napi_env env, napi_value exports)
{
    napi_value dmClass;
    napi_property_descriptor dmProperties[] = {
        DECLARE_NAPI_FUNCTION("release", ReleaseDeviceManager),
        DECLARE_NAPI_FUNCTION("getTrustedDeviceListSync", GetTrustedDeviceListSync),
        DECLARE_NAPI_FUNCTION("startDeviceDiscovery", StartDeviceDiscoverSync),
        DECLARE_NAPI_FUNCTION("stopDeviceDiscovery", StopDeviceDiscoverSync),
        DECLARE_NAPI_FUNCTION("authenticateDevice", AuthenticateDeviceSync),
        DECLARE_NAPI_FUNCTION("on", JsOn),
        DECLARE_NAPI_FUNCTION("off", JsOff)
        };

    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createDeviceManager", CreateDeviceManager),
    };

    HILOGD("DeviceManagerNapi::Init() is called!");
    NAPI_CALL(env,
        napi_define_class(env, DEVICE_MANAGER_NAPI_CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Constructor, nullptr,
            sizeof(dmProperties) / sizeof(dmProperties[0]), dmProperties, &dmClass));
    NAPI_CALL(env, napi_create_reference(env, dmClass, 1, &sConstructor_));
    NAPI_CALL(env, napi_set_named_property(env, exports, DEVICE_MANAGER_NAPI_CLASS_NAME.c_str(), dmClass));
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(static_prop) / sizeof(static_prop[0]), static_prop));
    HILOGI("All props and functions are configured..");
    return exports;
}

/*
 * Function registering all props and functions of ohos.distributedhardware
 */
static napi_value Export(napi_env env, napi_value exports)
{
    HILOGI("Export() is called!");
    DeviceManagerNapi::Init(env, exports);
    return exports;
}

/*
 * module define
 */
static napi_module g_dmModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Export,
    .nm_modname = "distributedhardware.devicemanager",
    .nm_priv = ((void *)0),
    .reserved = {0}
    };

/*
 * module register
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    HILOGI("RegisterModule() is called!");
    napi_module_register(&g_dmModule);
}
