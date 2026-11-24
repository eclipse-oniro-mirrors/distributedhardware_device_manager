/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_CONNECTOR_REFACTOR_H
#define SOFTBUS_CONNECTOR_REFACTOR_H

#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <set>
#include <string>
#include <vector>

#include "softbus_bus_center.h"
#include "dm_device_info.h"
#include "dm_publish_info.h"
#include "dm_subscribe_info.h"
#include "deviceprofile_connector.h"
#include "softbus_session.h"
#include "softbus_connector_callback.h"
#include "softbus_state_callback.h"
#include "softbus_leavelnn_callback.h"
#include "hichain_auth_connector.h"

namespace OHOS {
namespace DistributedHardware {

typedef struct DelInfoCache {
    int32_t userId {0};
    int32_t sessionKeyId {0};
    int32_t aclId {0};
    std::string credId;
    bool operator==(const DelInfoCache &other) const
    {
        return (userId == other.userId) && (credId == other.credId) &&
            (sessionKeyId == other.sessionKeyId) && (aclId == other.aclId);
    }
    bool operator<(const DelInfoCache &other) const
    {
        return aclId < other.aclId;
    }
} DelInfoCache;

class SoftbusConnector {
public:
    SoftbusConnector();
    ~SoftbusConnector();

    static void OnSoftbusJoinLNNResult(ConnectionAddr *addr,
        const char *networkId, int32_t result);
    static std::shared_ptr<ConnectionAddr> GetConnectAddr(
        const std::string &deviceId, std::string &connectAddr);
    static int32_t GetUdidByNetworkId(const char *networkId,
        std::string &udid);
    static int32_t GetUuidByNetworkId(const char *networkId,
        std::string &uuid);
    static std::string GetDeviceUdidByUdidHash(
        const std::string &udidHash);
    static void JoinLnn(const std::string &deviceId,
        bool isForceJoin = false);
    static void JoinLnnByHml(int32_t sessionId, int32_t sessionKeyId,
        int32_t remoteSessionKeyId, bool isForceJoin = false);
    static void JoinLnn(const std::string &deviceId,
        const std::string &remoteUdidHash);
    static void JoinLNNBySkId(int32_t sessionId, int32_t sessionKeyId,
        int32_t remoteSessionKeyId, std::string udid,
        std::string udidHash, bool isForceJoin = false);
    static void OnLeaveLNNResult(const char *networkId, int32_t retCode);

    int32_t RegisterConnectorCallback(
        std::shared_ptr<ISoftbusConnectorCallback> callback);
    int32_t UnRegisterConnectorCallback();
    int32_t RegisterSoftbusStateCallback(
        const std::shared_ptr<ISoftbusStateCallback> callback);
    int32_t UnRegisterSoftbusStateCallback();
    std::shared_ptr<SoftbusSession> GetSoftbusSession();
    void SortAclListDesc(const std::vector<AclHashItem> &remoteAllAclList,
        std::vector<std::string> &aclVerDesc,
        std::map<std::string, AclHashItem> &remoteAllAclMap);
    std::string MatchTargetVersion(const std::string &localVersion,
        const std::vector<std::string> &remoteVerDesc);
    bool HaveDeviceInMap(std::string deviceId);
    std::string GetDeviceUdidHashByUdid(const std::string &udid);
    void EraseUdidFromMap(const std::string &udid);
    std::string GetLocalDeviceName();
    std::string GetLocalDeviceNetworkId();
    int32_t GetLocalDeviceTypeId();
    int32_t AddMemberToDiscoverMap(const std::string &deviceId,
        std::shared_ptr<DeviceInfo> deviceInfo);
    std::string GetNetworkIdByDeviceId(const std::string &deviceId);
    void HandleDeviceOnline(std::string deviceId, int32_t authForm);
    void HandleDeviceOnline(std::string deviceId, int32_t authForm,
        const PeerDevInfo &peerDevInfo);
    void HandleDeviceOffline(std::string deviceId, const bool isOnline);
    void SetProcessInfo(ProcessInfo processInfo);
    bool CheckIsNeedJoinLnn(const std::string &udid,
        const std::string &deviceId);
    bool CheckIsOnline(const std::string &targetDeviceId);
    bool CheckIsOnline(const std::string &targetDeviceIdHash,
        bool isHash);
    void SetProcessInfoVec(std::vector<ProcessInfo> processInfoVec);
    std::vector<ProcessInfo> GetProcessInfo();
    void ClearProcessInfo();
    void SetChangeProcessInfo(ProcessInfo processInfo);
    std::vector<ProcessInfo> GetChangeProcessInfo();
    void ClearChangeProcessInfo();
    DmDeviceInfo GetDeviceInfoByDeviceId(const std::string &deviceId,
        std::string &uuid);
    void OnSessionOpened(int32_t sessionId, int32_t result);
    void SyncAclList();
    void SyncAclList(int32_t userId, std::string credId,
        int32_t sessionKeyId, int32_t aclId);
    int32_t SyncLocalAclListProcess(
        const DevUserInfo &localDevUserInfo,
        const DevUserInfo &remoteDevUserInfo,
        std::string remoteAclList, bool isDelImmediately);
    int32_t GetAclListHash(const DevUserInfo &localDevUserInfo,
        const DevUserInfo &remoteDevUserInfo, std::string &aclList);
    int32_t LeaveLNN(const std::string &pkgName,
        const std::string &networkId);
    void RegisterLeaveLNNCallback(
        std::shared_ptr<ISoftbusLeaveLNNCallback> callback);
    void UnRegisterLeaveLNNCallback();
    void DeleteCredential(const DelInfoCache &acl);
    bool CheckAclInDeleteCache(const int32_t aclId);

private:
    static std::shared_ptr<ConnectionAddr> SetAddrAndJson(
        const ConnectionAddr *addr, JsonObject &jsonPara,
        std::string &connectAddr);
    static void ConvertDeviceInfoToDmDevice(
        const DeviceInfo &deviceInfo, DmDeviceInfo &dmDeviceInfo);
    static void ConvertDeviceInfoToDmDevice(
        const DeviceInfo &deviceInfo,
        DmDeviceBasicInfo &dmDeviceBasicInfo);
    static ConnectionAddr *GetConnectAddrByType(
        DeviceInfo *deviceInfo, ConnectionAddrType type);
    static void ConvertNodeBasicInfoToDmDevice(
        const NodeBasicInfo &nodeBasicInfo,
        DmDeviceInfo &dmDeviceInfo);
    static std::shared_ptr<DeviceInfo> GetDeviceInfoFromMap(
        const std::string &deviceId);
    static std::shared_ptr<ConnectionAddr> TryGetAddr(
        DeviceInfo *deviceInfo, ConnectionAddrType type,
        JsonObject &jsonPara, std::string &connectAddr);
    static uint32_t GetAddrTypeMask(ConnectionAddrType type);
    static DmDeviceInfo FindDeviceInNodes(
        const std::string &deviceId, const char *deviceIdHash);
    static void RemoveTokenIdFromAppList(
        std::vector<std::string> &appList,
        const std::string &tokenId);
    static bool ConvertBleUdidHash(ConnectionAddr *addrInfo,
        const std::string &udidHash);
    static void UpdateExtraDataFromNodeInfo(
        const NodeBasicInfo &nodeBasicInfo,
        DmDeviceInfo &dmDeviceInfo);
    int32_t ParaseAclChecksumList(const std::string &jsonString,
        std::vector<AclHashItem> &remoteAllAclList);
    int32_t SyncLocalAclList5_1_0(const std::string localUdid,
        const std::string remoteUdid,
        DistributedDeviceProfile::AccessControlProfile &localAcl,
        std::vector<std::string> &acLStrList, bool isDelImmediately);
    int32_t GetLocalVersion(const std::string localUdid,
        const std::string remoteUdid, std::string &localVersion,
        DistributedDeviceProfile::AccessControlProfile &localAcl);
    void DoJoinLnn(const std::string &deviceId,
        const std::string &udidHash, bool isForceJoin);

private:
    static std::string remoteUdidHash_;
    std::shared_ptr<SoftbusSession> softbusSession_ {nullptr};
    std::shared_ptr<HiChainAuthConnector> hiChainAuthConnector_ {nullptr};
    std::shared_ptr<ISoftbusStateCallback> deviceStateManagerCallback_ {nullptr};
    static std::map<std::string, std::shared_ptr<DeviceInfo>>
        discoveryDeviceInfoMap_;
    static std::unordered_map<std::string, std::string> deviceUdidMap_;
    static std::vector<ProcessInfo> processInfoVec_;
    static std::vector<ProcessInfo> processChangeInfoVec_;
    static std::mutex discoveryDeviceInfoMutex_;
    static std::mutex deviceUdidLocks_;
    static std::mutex processInfoVecMutex_;
    static std::mutex processChangeInfoVecMutex_;
    static std::shared_ptr<ISoftbusConnectorCallback> connectorCallback_;
    static std::shared_ptr<ISoftbusLeaveLNNCallback> leaveLNNCallback_;
    static std::mutex leaveLNNMutex_;
    static std::map<std::string, std::string> leaveLnnPkgMap_;
    static std::mutex dmDelInfoMutex_;
    static std::set<DelInfoCache> dmDelInfoCache_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // SOFTBUS_CONNECTOR_REFACTOR_H