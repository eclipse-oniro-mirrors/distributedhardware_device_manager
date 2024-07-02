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

#include "discovery_manager.h"

#include <dlfcn.h>
#include <securec.h>

#include "softbus_common.h"

#include "dm_anonymous.h"
#include "dm_constants.h"
#include "parameter.h"

namespace OHOS {
namespace DistributedHardware {
const int32_t DISCOVERY_TIMEOUT = 120;
const uint16_t DM_INVALID_FLAG_ID = 0;
constexpr const char* LNN_DISC_CAPABILITY = "capability";
const std::string TYPE_MINE = "findDeviceMode";

#if !(defined(__LITEOS_M__) || defined(LITE_DEVICE))
static std::mutex comDependencyLoadLock;
constexpr const char* LIB_DM_COMDENPENDENCY_NAME = "libdevicemanagerdependency.z.so";
bool DiscoveryManager::isSoLoaded_ = false;
IDeviceProfileConnector* DiscoveryManager::dpConnector_ = nullptr;
void* DiscoveryManager::dpConnectorHandle_ = nullptr;
#endif

DiscoveryManager::DiscoveryManager(std::shared_ptr<SoftbusListener> softbusListener,
    std::shared_ptr<IDeviceManagerServiceListener> listener) : softbusListener_(softbusListener), listener_(listener)
{
    LOGI("DiscoveryManager constructor.");
}

DiscoveryManager::~DiscoveryManager()
{
#if !(defined(__LITEOS_M__) || defined(LITE_DEVICE))
    CloseCommonDependencyObj();
#endif
    LOGI("DiscoveryManager destructor.");
}

int32_t DiscoveryManager::EnableDiscoveryListener(const std::string &pkgName,
    const std::map<std::string, std::string> &discoverParam, const std::map<std::string, std::string> &filterOptions)
{
    LOGI("DiscoveryManager::EnableDiscoveryListener begin for pkgName = %{public}s.", pkgName.c_str());
    if (pkgName.empty()) {
        LOGE("Invalid parameter, pkgName is empty.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    DmSubscribeInfo dmSubInfo;
    dmSubInfo.subscribeId = DM_INVALID_FLAG_ID;
    dmSubInfo.mode = DmDiscoverMode::DM_DISCOVER_MODE_PASSIVE;
    dmSubInfo.medium = DmExchangeMedium::DM_BLE;
    dmSubInfo.freq = DmExchangeFreq::DM_LOW;
    dmSubInfo.isSameAccount = false;
    dmSubInfo.isWakeRemote = false;
    if (strcpy_s(dmSubInfo.capability, DM_MAX_DEVICE_CAPABILITY_LEN, DM_CAPABILITY_APPROACH) != EOK) {
        LOGE("capability copy err.");
        return ERR_DM_ENABLE_DISCOVERY_LISTENER_FAILED;
    }

    if (discoverParam.find(PARAM_KEY_META_TYPE) != discoverParam.end()) {
        std::string metaType = discoverParam.find(PARAM_KEY_META_TYPE)->second;
        LOGI("EnableDiscoveryListener, input MetaType = %{public}s in discoverParam map.", metaType.c_str());
    }
    if (discoverParam.find(PARAM_KEY_SUBSCRIBE_ID) != discoverParam.end()) {
        dmSubInfo.subscribeId = std::atoi((discoverParam.find(PARAM_KEY_SUBSCRIBE_ID)->second).c_str());
        {
            std::lock_guard<std::mutex> autoLock(subIdMapLocks_);
            pkgName2SubIdMap_[pkgName] = dmSubInfo.subscribeId;
        }
    }
    if (discoverParam.find(PARAM_KEY_DISC_CAPABILITY) != discoverParam.end()) {
        std::string capability = discoverParam.find(PARAM_KEY_DISC_CAPABILITY)->second;
        if (strcpy_s(dmSubInfo.capability, DM_MAX_DEVICE_CAPABILITY_LEN, capability.c_str()) != EOK) {
            LOGI("EnableDiscoveryListener failed, capability copy err.");
            return ERR_DM_ENABLE_DISCOVERY_LISTENER_FAILED;
        }
    }
    LOGI("EnableDiscoveryListener capability = %{public}s,", std::string(dmSubInfo.capability).c_str());
    {
        std::lock_guard<std::mutex> capLock(capabilityMapLocks_);
        capabilityMap_[pkgName] = std::string(dmSubInfo.capability);
    }

    int32_t ret = softbusListener_->RefreshSoftbusLNN(DM_PKG_NAME, dmSubInfo, LNN_DISC_CAPABILITY);
    if (ret != DM_OK) {
        LOGE("EnableDiscoveryListener failed, softbus refresh lnn ret: %{public}d.", ret);
        return ERR_DM_ENABLE_DISCOVERY_LISTENER_FAILED;
    }
    softbusListener_->RegisterSoftbusLnnOpsCbk(pkgName, shared_from_this());
    return DM_OK;
}

int32_t DiscoveryManager::DisableDiscoveryListener(const std::string &pkgName,
    const std::map<std::string, std::string> &extraParam)
{
    LOGI("DiscoveryManager::DisableDiscoveryListener begin for pkgName = %{public}s.", pkgName.c_str());
    if (pkgName.empty()) {
        LOGE("Invalid parameter, pkgName is empty.");
        return ERR_DM_INPUT_PARA_INVALID;
    }

    if (extraParam.find(PARAM_KEY_META_TYPE) != extraParam.end()) {
        LOGI("DisableDiscoveryListener, input MetaType = %{public}s",
            (extraParam.find(PARAM_KEY_META_TYPE)->second).c_str());
    }
    uint16_t subscribeId = DM_INVALID_FLAG_ID;
    if (extraParam.find(PARAM_KEY_SUBSCRIBE_ID) != extraParam.end()) {
        subscribeId = std::atoi((extraParam.find(PARAM_KEY_SUBSCRIBE_ID)->second).c_str());
        {
            std::lock_guard<std::mutex> autoLock(subIdMapLocks_);
            pkgName2SubIdMap_.erase(pkgName);
        }
    }
    {
        std::lock_guard<std::mutex> capLock(capabilityMapLocks_);
        if (capabilityMap_.find(pkgName) != capabilityMap_.end()) {
            capabilityMap_.erase(pkgName);
        }
    }
    softbusListener_->UnRegisterSoftbusLnnOpsCbk(pkgName);
    return softbusListener_->StopRefreshSoftbusLNN(subscribeId);
}

int32_t DiscoveryManager::StartDiscovering(const std::string &pkgName,
                                           const std::map<std::string, std::string> &discoverParam,
                                           const std::map<std::string, std::string> &filterOptions)
{
    LOGI("DiscoveryManager::StartDiscovering begin for pkgName = %{public}s.", pkgName.c_str());
    if (pkgName.empty()) {
        LOGE("Invalid parameter, pkgName is empty.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    DmSubscribeInfo dmSubInfo;
    ConfigDiscParam(discoverParam, &dmSubInfo);
    if (HandleDiscoveryQueue(pkgName, dmSubInfo.subscribeId, filterOptions) != DM_OK) {
        return ERR_DM_DISCOVERY_REPEATED;
    }

    bool isStandardMetaNode = true;
    if (discoverParam.find(PARAM_KEY_META_TYPE) != discoverParam.end()) {
        MetaNodeType metaType = (MetaNodeType)(std::atoi((discoverParam.find(PARAM_KEY_META_TYPE)->second).c_str()));
        isStandardMetaNode = (metaType == MetaNodeType::PROXY_TRANSMISION);
    }

    softbusListener_->RegisterSoftbusLnnOpsCbk(pkgName, shared_from_this());
    StartDiscoveryTimer(pkgName);

    auto it = filterOptions.find(PARAM_KEY_FILTER_OPTIONS);
    nlohmann::json jsonObject = nlohmann::json::parse(it->second, nullptr, false);
    if (!jsonObject.is_discarded() && jsonObject.contains(TYPE_MINE)) {
        return StartDiscovering4MineLibary(pkgName, dmSubInfo, it->second);
    }

    int32_t ret = isStandardMetaNode ? StartDiscoveringNoMetaType(pkgName, dmSubInfo, discoverParam) :
            StartDiscovering4MetaType(pkgName, dmSubInfo, discoverParam);
    if (ret != DM_OK) {
        LOGE("StartDiscovering for meta node process failed, ret = %{public}d", ret);
        return ERR_DM_START_DISCOVERING_FAILED;
    }
    return ret;
}

void DiscoveryManager::ConfigDiscParam(const std::map<std::string, std::string> &discoverParam,
    DmSubscribeInfo *dmSubInfo)
{
    LOGI("DiscoveryManager::ConfigDiscParam");
    if (dmSubInfo == nullptr) {
        LOGE("ConfigDiscParam failed, dmSubInfo is nullptr.");
        return;
    }
    dmSubInfo->subscribeId = DM_INVALID_FLAG_ID;
    dmSubInfo->mode = DmDiscoverMode::DM_DISCOVER_MODE_ACTIVE;
    dmSubInfo->medium = DmExchangeMedium::DM_AUTO;
    dmSubInfo->freq = DmExchangeFreq::DM_LOW;
    dmSubInfo->isSameAccount = false;
    dmSubInfo->isWakeRemote = false;
    if (discoverParam.find(PARAM_KEY_SUBSCRIBE_ID) != discoverParam.end()) {
        dmSubInfo->subscribeId = std::atoi((discoverParam.find(PARAM_KEY_SUBSCRIBE_ID)->second).c_str());
    }
    if (discoverParam.find(PARAM_KEY_DISC_MEDIUM) != discoverParam.end()) {
        int32_t medium = std::atoi((discoverParam.find(PARAM_KEY_DISC_MEDIUM)->second).c_str());
        dmSubInfo->medium = static_cast<DmExchangeMedium>(medium);
    }
    if (discoverParam.find(PARAM_KEY_DISC_FREQ) != discoverParam.end()) {
        int32_t freq = std::atoi((discoverParam.find(PARAM_KEY_DISC_FREQ)->second).c_str());
        dmSubInfo->freq = static_cast<DmExchangeFreq>(freq);
    }
    if (discoverParam.find(PARAM_KEY_DISC_MODE) != discoverParam.end()) {
        dmSubInfo->mode =
            static_cast<DmDiscoverMode>(std::atoi((discoverParam.find(PARAM_KEY_DISC_MODE)->second).c_str()));
    }
}

int32_t DiscoveryManager::StartDiscovering4MineLibary(const std::string &pkgName, DmSubscribeInfo &dmSubInfo,
    const std::string &searchJson)
{
    if (strcpy_s(dmSubInfo.capability, DM_MAX_DEVICE_CAPABILITY_LEN, DM_CAPABILITY_OSD) != EOK) {
        LOGE("capability copy err.");
        return ERR_DM_START_DISCOVERING_FAILED;
    }
    LOGI("StartDiscovering for mine meta node process, pkgName = %{public}s, capability = %{public}s",
        pkgName.c_str(), std::string(dmSubInfo.capability).c_str());
    {
        std::lock_guard<std::mutex> capLock(capabilityMapLocks_);
        capabilityMap_[pkgName] = std::string(dmSubInfo.capability);
    }
    int32_t ret = mineSoftbusListener_->RefreshSoftbusLNN(pkgName, searchJson, dmSubInfo);
    if (ret != DM_OK) {
        LOGE("StartDiscovering for meta node process failed, ret = %{public}d", ret);
        return ERR_DM_START_DISCOVERING_FAILED;
    }
    return ret;
}

int32_t DiscoveryManager::StartDiscoveringNoMetaType(const std::string &pkgName, DmSubscribeInfo &dmSubInfo,
    const std::map<std::string, std::string> &param)
{
    (void)param;
    if (strcpy_s(dmSubInfo.capability, DM_MAX_DEVICE_CAPABILITY_LEN, DM_CAPABILITY_OSD) != EOK) {
        LOGE("capability copy err.");
        return ERR_DM_START_DISCOVERING_FAILED;
    }
    LOGI("StartDiscovering for standard meta node process, pkgName = %{public}s, capability = %{public}s",
        pkgName.c_str(), std::string(dmSubInfo.capability).c_str());

    {
        std::lock_guard<std::mutex> capLock(capabilityMapLocks_);
        capabilityMap_[pkgName] = std::string(dmSubInfo.capability);
    }
    int32_t ret = softbusListener_->RefreshSoftbusLNN(DM_PKG_NAME, dmSubInfo, LNN_DISC_CAPABILITY);
    if (ret != DM_OK) {
        LOGE("StartDiscoveringNoMetaType failed, softbus refresh lnn ret: %{public}d.", ret);
    }
    return ret;
}

int32_t DiscoveryManager::StartDiscovering4MetaType(const std::string &pkgName, DmSubscribeInfo &dmSubInfo,
    const std::map<std::string, std::string> &param)
{
    LOGI("StartDiscovering for meta node process, input metaType = %{public}s, pkgName = %{public}s",
         (param.find(PARAM_KEY_META_TYPE)->second).c_str(), pkgName.c_str());
    MetaNodeType metaType = (MetaNodeType)(std::atoi((param.find(PARAM_KEY_META_TYPE)->second).c_str()));
    switch (metaType) {
        case MetaNodeType::PROXY_SHARE:
            LOGI("StartDiscovering4MetaType for share meta node process.");
            if (strcpy_s(dmSubInfo.capability, DM_MAX_DEVICE_CAPABILITY_LEN, DM_CAPABILITY_SHARE) != EOK) {
                LOGE("capability copy error.");
                return ERR_DM_FAILED;
            }
            break;
        case MetaNodeType::PROXY_WEAR:
            LOGI("StartDiscovering4MetaType for wear meta node process.");
            if (strcpy_s(dmSubInfo.capability, DM_MAX_DEVICE_CAPABILITY_LEN, DM_CAPABILITY_WEAR) != EOK) {
                LOGE("capability copy error.");
                return ERR_DM_FAILED;
            }
            break;
        case MetaNodeType::PROXY_CASTPLUS:
            LOGI("StartDiscovering4MetaType for cast_plus meta node process.");
            if (strcpy_s(dmSubInfo.capability, DM_MAX_DEVICE_CAPABILITY_LEN, DM_CAPABILITY_CASTPLUS) != EOK) {
                LOGE("capability copy error.");
                return ERR_DM_FAILED;
            }
            break;
        default:
            LOGE("StartDiscovering4MetaType failed, unsupport meta type : %{public}d.", metaType);
            return ERR_DM_UNSUPPORTED_METHOD;
    }

    std::string customData = "";
    if (param.find(PARAM_KEY_CUSTOM_DATA) != param.end()) {
        customData = param.find(PARAM_KEY_CUSTOM_DATA)->second;
    }
    LOGI("StartDiscovering4MetaType capability = %{public}s,", std::string(dmSubInfo.capability).c_str());
    {
        std::lock_guard<std::mutex> capLock(capabilityMapLocks_);
        capabilityMap_[pkgName] =std::string(dmSubInfo.capability);
    }

    int32_t ret = softbusListener_->RefreshSoftbusLNN(DM_PKG_NAME, dmSubInfo, customData);
    if (ret != DM_OK) {
        LOGE("StartDiscovering4MetaType failed, softbus refresh lnn ret: %{public}d.", ret);
    }
    return ret;
}

int32_t DiscoveryManager::StopDiscovering(const std::string &pkgName, uint16_t subscribeId)
{
    LOGI("DiscoveryManager::StopDiscovering begin for pkgName = %{public}s.", pkgName.c_str());
    if (pkgName.empty()) {
        LOGE("Invalid parameter, pkgName is empty.");
        return ERR_DM_INPUT_PARA_INVALID;
    }
    {
        std::lock_guard<std::mutex> autoLock(locks_);
        if (pkgNameSet_.find(pkgName) != pkgNameSet_.end()) {
            pkgNameSet_.erase(pkgName);
        }

        if (discoveryContextMap_.find(pkgName) != discoveryContextMap_.end()) {
            discoveryContextMap_.erase(pkgName);
            timer_->DeleteTimer(pkgName);
        }
    }
    {
        std::lock_guard<std::mutex> capLock(capabilityMapLocks_);
        if (capabilityMap_.find(pkgName) != capabilityMap_.end()) {
            capabilityMap_.erase(pkgName);
        }
    }
    softbusListener_->UnRegisterSoftbusLnnOpsCbk(pkgName);
#if (defined(MINE_HARMONY))
    return mineSoftbusListener_->StopRefreshSoftbusLNN(subscribeId);
#else
    return softbusListener_->StopRefreshSoftbusLNN(subscribeId);
#endif
}

void DiscoveryManager::OnDeviceFound(const std::string &pkgName, const DmDeviceInfo &info, bool isOnline)
{
    DiscoveryContext discoveryContext;
    DiscoveryFilter filter;
    DeviceFilterPara filterPara;
    filterPara.isOnline = false;
    filterPara.range = info.range;
    filterPara.deviceType = info.deviceTypeId;
    std::string deviceIdHash = static_cast<std::string>(info.deviceId);
    if (isOnline && GetDeviceAclParam(pkgName, deviceIdHash, filterPara.isOnline, filterPara.authForm) != DM_OK) {
        LOGE("The found device get online param failed.");
    }
    nlohmann::json jsonObject = nlohmann::json::parse(info.extraData, nullptr, false);
    if (jsonObject.is_discarded()) {
        LOGE("OnDeviceFound jsonStr error");
        return;
    }
    if (!IsInt32(jsonObject, PARAM_KEY_DISC_CAPABILITY)) {
        LOGE("err json string: %{public}s", PARAM_KEY_DISC_CAPABILITY);
        return;
    }
    int32_t capabilityType = jsonObject[PARAM_KEY_DISC_CAPABILITY].get<int32_t>();
    uint16_t subscribeId = 0;
    {
        std::lock_guard<std::mutex> autoLock(subIdMapLocks_);
        subscribeId = pkgName2SubIdMap_[pkgName];
    }
    {
        std::lock_guard<std::mutex> autoLock(locks_);
        auto iter = discoveryContextMap_.find(pkgName);
        if (iter == discoveryContextMap_.end()) {
            if (capabilityMap_.find(pkgName) != capabilityMap_.end() &&
                CompareCapability(capabilityType, capabilityMap_[pkgName])) {
                LOGI("OnDeviceFound, pkgName = %{public}s, cabability = %{public}d", pkgName.c_str(), capabilityType);
                listener_->OnDeviceFound(pkgName, subscribeId, info);
                return;
            }
        }
        discoveryContext = iter->second;
    }
    if (filter.IsValidDevice(discoveryContext.filterOp, discoveryContext.filters, filterPara)) {
        if (capabilityMap_.find(pkgName) != capabilityMap_.end() &&
            CompareCapability(capabilityType, capabilityMap_[pkgName])) {
            LOGI("OnDeviceFound, pkgName = %{public}s, cabability = %{public}d", pkgName.c_str(), capabilityType);
            listener_->OnDeviceFound(pkgName, discoveryContext.subscribeId, info);
        }
    }
}

bool DiscoveryManager::CompareCapability(int32_t capabilityType, const std::string &capabilityStr)
{
    for (uint32_t i = 0; i < sizeof(g_capabilityMap) / sizeof(g_capabilityMap[0]); i++) {
        if (strcmp(capabilityStr.c_str(), g_capabilityMap[i].capability) == 0) {
            LOGD("capabilityType: %{public}d, capabilityStr: %{public}s", capabilityType, capabilityStr.c_str());
            return ((capabilityType >> static_cast<int32_t>(g_capabilityMap[i].bitmap)) & 1);
        }
    }
    return false;
}

void DiscoveryManager::OnDiscoveringResult(const std::string &pkgName, int32_t subscribeId, int32_t result)
{
    LOGI("DiscoveryManager::OnDiscoveringResult, subscribeId = %{public}d, result = %{public}d.", subscribeId, result);
    if (pkgName.empty() || (listener_ == nullptr)) {
        LOGE("DiscoveryManager::OnDiscoveringResult failed, IDeviceManagerServiceListener is null.");
        return;
    }
    if (result == 0) {
        std::lock_guard<std::mutex> autoLock(locks_);
        discoveryContextMap_[pkgName].subscribeId = (uint32_t)subscribeId;
        listener_->OnDiscoverySuccess(pkgName, subscribeId);
        return;
    }
    {
        std::lock_guard<std::mutex> autoLock(locks_);
        if (pkgNameSet_.find(pkgName) != pkgNameSet_.end()) {
            pkgNameSet_.erase(pkgName);
        }
        if (discoveryContextMap_.find(pkgName) != discoveryContextMap_.end()) {
            discoveryContextMap_.erase(pkgName);
            timer_->DeleteTimer(pkgName);
        }
    }
    {
        std::lock_guard<std::mutex> capLock(capabilityMapLocks_);
        if (capabilityMap_.find(pkgName) != capabilityMap_.end()) {
            capabilityMap_.erase(pkgName);
        }
    }
    listener_->OnDiscoveryFailed(pkgName, (uint32_t)subscribeId, result);
    softbusListener_->StopRefreshSoftbusLNN(subscribeId);
}

void DiscoveryManager::StartDiscoveryTimer(const std::string &pkgName)
{
    if (timer_ == nullptr) {
        timer_ = std::make_shared<DmTimer>();
    }
    timer_->StartTimer(pkgName, DISCOVERY_TIMEOUT,
        [this] (std::string name) {
            DiscoveryManager::HandleDiscoveryTimeout(name);
        });
}

int32_t DiscoveryManager::HandleDiscoveryQueue(const std::string &pkgName, uint16_t subscribeId,
    const std::map<std::string, std::string> &filterOps)
{
    std::string filterData = "";
    if (filterOps.find(PARAM_KEY_FILTER_OPTIONS) != filterOps.end()) {
        filterData = filterOps.find(PARAM_KEY_FILTER_OPTIONS)->second;
    }
    DeviceFilterOption dmFilter;
    if ((dmFilter.TransformToFilter(filterData) != DM_OK) && (dmFilter.TransformFilterOption(filterData) != DM_OK)) {
        return ERR_DM_INPUT_PARA_INVALID;
    }
    {
        std::lock_guard<std::mutex> autoLock(locks_);
        if (pkgNameSet_.find(pkgName) == pkgNameSet_.end()) {
            pkgNameSet_.emplace(pkgName);
            DiscoveryContext context = {pkgName, filterData, subscribeId, dmFilter.filterOp_, dmFilter.filters_};
            discoveryContextMap_.emplace(pkgName, context);
            return DM_OK;
        } else {
            LOGE("DiscoveryManager::HandleDiscoveryQueue repeated, pkgName : %{public}s.", pkgName.c_str());
            return ERR_DM_DISCOVERY_REPEATED;
        }
    }
}

void DiscoveryManager::HandleDiscoveryTimeout(const std::string &pkgName)
{
    LOGI("DiscoveryManager::HandleDiscoveryTimeout");
    uint16_t subscribeId = 0;
    {
        std::lock_guard<std::mutex> autoLock(locks_);
        if (pkgNameSet_.find(pkgName) == pkgNameSet_.end()) {
            LOGE("HandleDiscoveryTimeout: pkgName: %{public}s is not exist.", pkgName.c_str());
            return;
        }
        auto iter = discoveryContextMap_.find(pkgName);
        if (iter == discoveryContextMap_.end()) {
            LOGE("HandleDiscoveryTimeout: subscribeId not found by pkgName %{public}s.",
                GetAnonyString(pkgName).c_str());
            return;
        }
        subscribeId = discoveryContextMap_[pkgName].subscribeId;
    }
    StopDiscovering(pkgName, subscribeId);
}

int32_t DiscoveryManager::GetDeviceAclParam(const std::string &pkgName, std::string deviceId,
    bool &isOnline, int32_t &authForm)
{
#if !(defined(__LITEOS_M__) || defined(LITE_DEVICE))
    LOGI("Get deviceId = %{public}s isOnline and authForm.", GetAnonyString(deviceId).c_str());
    char localDeviceId[DEVICE_UUID_LENGTH];
    GetDevUdid(localDeviceId, DEVICE_UUID_LENGTH);
    std::string requestDeviceId = static_cast<std::string>(localDeviceId);
    DmDiscoveryInfo discoveryInfo;
    discoveryInfo.pkgname = pkgName;
    discoveryInfo.localDeviceId = requestDeviceId;
    discoveryInfo.remoteDeviceIdHash = deviceId;
    if (DiscoveryManager::IsCommonDependencyReady() && DiscoveryManager::GetCommonDependencyObj() != nullptr) {
        if (DiscoveryManager::GetCommonDependencyObj()->GetDeviceAclParam(discoveryInfo, isOnline, authForm) != DM_OK) {
            LOGE("GetDeviceAclParam failed.");
            return ERR_DM_FAILED;
        }
    }
#endif
    return DM_OK;
}

#if !(defined(__LITEOS_M__) || defined(LITE_DEVICE))
IDeviceProfileConnector* DiscoveryManager::GetCommonDependencyObj()
{
    return dpConnector_;
}

bool DiscoveryManager::IsCommonDependencyReady()
{
    LOGI("DiscoveryManager::IsCommonDependencyReady.");
    std::lock_guard<std::mutex> lock(comDependencyLoadLock);
    if (isSoLoaded_ && dpConnector_ != nullptr && dpConnectorHandle_ != nullptr) {
        LOGI("IsCommonDependencyReady already.");
        return true;
    }
    char path[PATH_MAX + 1] = {0x00};
    std::string soName = std::string(DM_LIB_LOAD_PATH) + std::string(LIB_DM_COMDENPENDENCY_NAME);
    if ((soName.length() == 0) || (soName.length() > PATH_MAX) || (realpath(soName.c_str(), path) == nullptr)) {
        LOGE("File %{public}s canonicalization failed.", soName.c_str());
        return false;
    }
    dpConnectorHandle_ = dlopen(path, RTLD_NOW | RTLD_NODELETE);
    if (dpConnectorHandle_ == nullptr) {
        LOGE("load libdevicemanagerdependency so %{public}s failed, errMsg: %{public}s.", soName.c_str(), dlerror());
        return false;
    }
    dlerror();
    auto func = (CreateDpConnectorFuncPtr)dlsym(dpConnectorHandle_, "CreateDpConnectorInstance");
    if (dlerror() != nullptr || func == nullptr) {
        dlclose(dpConnectorHandle_);
        LOGE("Create object function is not exist.");
        return false;
    }
    dpConnector_ = func();
    isSoLoaded_ = true;
    LOGI("IsCommonDependencyReady success.");
    return true;
}

bool DiscoveryManager::CloseCommonDependencyObj()
{
    LOGI("DiscoveryManager::CloseCommonDependencyObj start.");
    std::lock_guard<std::mutex> lock(comDependencyLoadLock);
    if (!isSoLoaded_ && (dpConnector_ == nullptr) && (dpConnectorHandle_ == nullptr)) {
        return true;
    }

    int32_t ret = dlclose(dpConnectorHandle_);
    if (ret != 0) {
        LOGE("close libdevicemanagerdependency failed ret = %{public}d.", ret);
        return false;
    }
    isSoLoaded_ = false;
    dpConnector_ = nullptr;
    dpConnectorHandle_ = nullptr;
    LOGI("close libdevicemanagerdependency so success.");
    return true;
}
#endif
} // namespace DistributedHardware
} // namespace OHOS
