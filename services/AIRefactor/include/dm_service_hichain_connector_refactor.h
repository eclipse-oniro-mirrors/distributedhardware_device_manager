/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DM_SERVICE_HICHAIN_CONNECTOR_REFACTOR_H
#define OHOS_DM_SERVICE_HICHAIN_CONNECTOR_REFACTOR_H

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "device_auth.h"
#include "device_auth_defines.h"
#include "dm_device_info.h"
#include "json_object.h"
#include "dm_single_instance.h"

namespace OHOS {
namespace DistributedHardware {
struct DmGroupInfo {
    std::string groupName;
    std::string groupId;
    std::string groupOwner;
    int32_t groupType;
    int32_t groupVisibility;
    std::string userId;

    DmGroupInfo() : groupName(""), groupId(""), groupOwner(""), groupType(0),
        groupVisibility(0), userId("") {}
};

void FromJson(const JsonItemObject &jsonObject, DmGroupInfo &groupInfo);

class IDmServiceGroupResCallback {
public:
    virtual void OnGroupResult(int64_t requestId, int32_t action, const std::string &resultInfo) = 0;
};

class DmServiceHiChainConnector {
public:
    static void onFinish(int64_t requestId, int operationCode, const char *returnData);
    static void onError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn);

public:
    DmServiceHiChainConnector();
    ~DmServiceHiChainConnector();

    int32_t CreateGroup(int64_t requestId, int32_t authType, const std::string &userId,
        JsonObject &jsonOutObj);
    int32_t DeleteGroup(std::string &groupId);
    int32_t DeleteGroup(int64_t requestId_, const std::string &userId, const int32_t authType);
    bool GetGroupInfo(const std::string &queryParams, std::vector<DmGroupInfo> &groupList);
    bool GetGroupInfo(const int32_t userId, const std::string &queryParams,
        std::vector<DmGroupInfo> &groupList);
    bool GetGroupInfoExt(const int32_t userId, const std::string &queryParams,
        std::vector<DmGroupInfo> &groupList);
    bool GetGroupInfoCommon(const int32_t userId, const std::string &queryParams,
        const char *pkgName, std::vector<DmGroupInfo> &groupList);
    int32_t RegisterHiChainGroupCallback(
        const std::shared_ptr<IDmServiceGroupResCallback> &callback);
    int32_t UnRegisterHiChainGroupCallback();
    int32_t addMultiMembers(const int32_t groupType, const std::string &userId,
        const JsonObject &jsonDeviceList);
    int32_t deleteMultiMembers(const int32_t groupType, const std::string &userId,
        const JsonObject &jsonDeviceList);
    int32_t addMultiMembersExt(const std::string &credentialInfo);

private:
    bool IsRedundanceGroup(const std::string &userId, int32_t authType,
        std::vector<DmGroupInfo> &groupList);
    void DealRedundanceGroup(const std::string &userId, int32_t authType);
    void DeleteRedundanceGroup(std::string &userId);
    int32_t GetGroupId(const std::string &userId, const int32_t groupType,
        std::string &groupId);
    int32_t ParseRemoteCredential(const int32_t groupType, const std::string &userId,
        const JsonObject &jsonDeviceList, std::string &params, int32_t &osAccountUserId);
    int32_t GetGroupIdExt(const std::string &userId, const int32_t groupType,
        std::string &groupId, std::string &groupOwner);
    int32_t ParseRemoteCredentialExt(const std::string &credentialInfo,
        std::string &params, std::string &groupOwner);
    int32_t GetJsonInt(const JsonObject &jsonObj, const std::string &key);
    std::string GetJsonStr(const JsonObject &jsonObj, const std::string &key);

    static void HandleCreateGroupFinish(int64_t requestId, const std::string &data);
    static void HandleDisbandGroupFinish(int64_t requestId, const std::string &data);
    static void HandleCreateGroupError(int64_t requestId, const std::string &data);
    static void HandleDisbandGroupError(int64_t requestId, const std::string &data);
    static void NotifyGroupResult(int64_t requestId, int32_t action,
        const std::string &data, bool &flag);
    static void ClearSensitiveString(std::string &str);
    int32_t BuildCreateGroupParams(const std::string &userId, int32_t authType,
        JsonObject &jsonOutObj, std::string &localDeviceId, JsonObject &jsonObj);
    int32_t WaitForCreateGroupResult();
    int32_t WaitForDeleteGroupResult();
    int32_t FindGroupIdByUserId(const std::vector<DmGroupInfo> &groupList,
        const std::string &userId, std::string &groupId);
    int32_t DoDeleteGroup(int64_t requestId, const std::string &groupId);
    bool ParseGroupInfoArray(const std::string &relatedGroups,
        std::vector<DmGroupInfo> &groupList);
    int32_t BuildCredentialParams(const JsonObject &jsonObject, int32_t groupType,
        const std::string &groupId, const std::string &userId, std::string &params);

private:
    const DeviceGroupManager *deviceGroupManager_ = nullptr;
    DeviceAuthCallback deviceAuthCallback_;
    static std::shared_ptr<IDmServiceGroupResCallback> hiChainResCallback_;
    static int32_t networkStyle_;
    static bool createGroupFlag_;
    static bool deleteGroupFlag_;
    static bool groupIsRedundance_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_SERVICE_HICHAIN_CONNECTOR_REFACTOR_H
