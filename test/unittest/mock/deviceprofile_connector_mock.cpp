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

#include "deviceprofile_connector_mock.h"

#include "gtest/gtest.h"

namespace OHOS {
namespace DistributedHardware {
DM_IMPLEMENT_SINGLE_INSTANCE(DeviceProfileConnector);
std::vector<DistributedDeviceProfile::AccessControlProfile> DeviceProfileConnector::GetAllAccessControlProfile()
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->GetAllAccessControlProfile();
}

int32_t DeviceProfileConnector::HandleDevUnBindEvent(int32_t remoteUserId, const std::string &remoteUdid,
    const std::string &localUdid, DmOfflineParam &offlineParam)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->HandleDevUnBindEvent(remoteUserId, remoteUdid,
        localUdid, offlineParam);
}

int32_t DeviceProfileConnector::HandleAccountLogoutEvent(int32_t remoteUserId, const std::string &remoteAccountHash,
    const std::string &remoteUdid, const std::string &localUdid)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->HandleAccountLogoutEvent(remoteUserId, remoteAccountHash,
        remoteUdid, localUdid);
}

uint32_t DeviceProfileConnector::CheckBindType(std::string trustDeviceId, std::string requestDeviceId)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->CheckBindType(trustDeviceId, requestDeviceId);
}

std::map<int32_t, int32_t> DeviceProfileConnector::GetUserIdAndBindLevel(const std::string &localUdid,
    const std::string &peerUdid)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->GetUserIdAndBindLevel(localUdid, peerUdid);
}

bool DeviceProfileConnector::DeleteAclForAccountLogOut(const std::string &localUdid, int32_t localUserId,
    const std::string &peerUdid, int32_t peerUserId, DmOfflineParam &offlineParam)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->DeleteAclForAccountLogOut(localUdid, localUserId,
        peerUdid, peerUserId, offlineParam);
}

DmOfflineParam DeviceProfileConnector::HandleAppUnBindEvent(int32_t remoteUserId,
    const std::string &remoteUdid, int32_t tokenId, const std::string &localUdid)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->HandleAppUnBindEvent(remoteUserId, remoteUdid,
        tokenId, localUdid);
}

std::multimap<std::string, int32_t> DeviceProfileConnector::GetDevIdAndUserIdByActHash(const std::string &localUdid,
    const std::string &peerUdid, int32_t peerUserId, const std::string &peerAccountHash)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->GetDevIdAndUserIdByActHash(localUdid, peerUdid,
        peerUserId, peerAccountHash);
}

std::vector<int32_t> DeviceProfileConnector::SyncAclByBindType(std::string pkgName, std::vector<int32_t> bindTypeVec,
    std::string localDeviceId, std::string targetDeviceId)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->SyncAclByBindType(pkgName, bindTypeVec,
        localDeviceId, targetDeviceId);
}

std::vector<int32_t> DeviceProfileConnector::GetBindTypeByPkgName(std::string pkgName, std::string requestDeviceId,
    std::string trustUdid)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->GetBindTypeByPkgName(pkgName,
        requestDeviceId, trustUdid);
}

DmOfflineParam DeviceProfileConnector::DeleteAccessControlList(const std::string &pkgName,
    const std::string &localDeviceId, const std::string &remoteDeviceId,
    int32_t bindLevel, const std::string &extra)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->DeleteAccessControlList(pkgName, localDeviceId,
        remoteDeviceId, bindLevel, extra);
}

void DeviceProfileConnector::DeleteAclForRemoteUserRemoved(std::string peerUdid, int32_t peerUserId,
    std::vector<int32_t> &userIds, DmOfflineParam &offlineParam)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->DeleteAclForRemoteUserRemoved(peerUdid, peerUserId,
        userIds, offlineParam);
}

DmOfflineParam DeviceProfileConnector::HandleAppUnBindEvent(int32_t remoteUserId,
    const std::string &remoteUdid, int32_t tokenId, const std::string &localUdid, int32_t peerTokenId)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->HandleAppUnBindEvent(remoteUserId, remoteUdid,
        tokenId, localUdid, peerTokenId);
}

std::unordered_map<std::string, DmAuthForm> DeviceProfileConnector::GetAppTrustDeviceList(const std::string &pkgName,
    const std::string &deviceId)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->GetAppTrustDeviceList(pkgName, deviceId);
}

int32_t DeviceProfileConnector::CheckDeviceInfoPermission(const std::string &localUdid, const std::string &peerDeviceId)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->CheckDeviceInfoPermission(localUdid, peerDeviceId);
}

int32_t DeviceProfileConnector::GetLocalServiceInfoByBundleNameAndPinExchangeType(
    const std::string& bundleName, int32_t pinExchangeType, DistributedDeviceProfile::LocalServiceInfo &serviceInfo)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->GetLocalServiceInfoByBundleNameAndPinExchangeType(
        bundleName, pinExchangeType, serviceInfo);
}

int32_t DeviceProfileConnector::PutSessionKey(int32_t userId, const std::vector<unsigned char> &sessionKeyArray,
    int32_t &sessionKeyId)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->PutSessionKey(userId, sessionKeyArray, sessionKeyId);
}

int32_t DeviceProfileConnector::PutLocalServiceInfo(
    const DistributedDeviceProfile::LocalServiceInfo &localServiceInfo)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->PutLocalServiceInfo(localServiceInfo);
}

int32_t DeviceProfileConnector::DeleteLocalServiceInfo(const std::string &bundleName, int32_t pinExchangeType)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->DeleteLocalServiceInfo(bundleName, pinExchangeType);
}

int32_t DeviceProfileConnector::UpdateLocalServiceInfo(
    const DistributedDeviceProfile::LocalServiceInfo &localServiceInfo)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->UpdateLocalServiceInfo(localServiceInfo);
}

bool DeviceProfileConnector::CheckAclStatusAndForegroundNotMatch(const std::string &localUdid,
    const std::vector<int32_t> &foregroundUserIds, const std::vector<int32_t> &backgroundUserIds)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->CheckAclStatusAndForegroundNotMatch(localUdid,
        foregroundUserIds, backgroundUserIds);
}

std::map<std::string, int32_t> DeviceProfileConnector::GetDeviceIdAndBindLevel(std::vector<int32_t> userIds,
    const std::string &localUdid)
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->GetDeviceIdAndBindLevel(userIds, localUdid);
}

std::vector<DistributedDeviceProfile::AccessControlProfile> DeviceProfileConnector::GetAllAclIncludeLnnAcl()
{
    return DmDeviceProfileConnector::dmDeviceProfileConnector->GetAllAclIncludeLnnAcl();
}
} // namespace DistributedHardware
} // namespace OHOS