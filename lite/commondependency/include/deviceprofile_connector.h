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


#ifndef DM_DEVICEPROFILE_CONNECTOR_H
#define DM_DEVICEPROFILE_CONNECTOR_H

#include <stdint.h>
#include <stdbool.h>
#include "dm_container.h"
#include "dm_device_info_c.h"
#include "dm_single_instance.h"
#include "dm_anonymous.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DM_EXPORT
#define DM_EXPORT __attribute__((visibility("default")))
#endif

DM_EXPORT extern const uint32_t DM_INVALIED_TYPE;
DM_EXPORT extern const uint32_t DM_APP_PEER_TO_PEER_TYPE;
DM_EXPORT extern const uint32_t DM_APP_ACROSS_ACCOUNT_TYPE;
DM_EXPORT extern const uint32_t DM_SHARE_TYPE;
DM_EXPORT extern const uint32_t DM_DEVICE_PEER_TO_PEER_TYPE;
DM_EXPORT extern const uint32_t DM_DEVICE_ACROSS_ACCOUNT_TYPE;
DM_EXPORT extern const uint32_t DM_IDENTICAL_ACCOUNT_TYPE;
DM_EXPORT extern const uint32_t DM_SERVICE_PEER_TO_PEER_TYPE;
DM_EXPORT extern const uint32_t DM_SERVICE_ACROSS_ACCOUNT_TYPE;

DM_EXPORT extern const uint32_t DM_DM_INVALIED_TYPE;
DM_EXPORT extern const uint32_t DM_BIND_LEVEL_USER;
DM_EXPORT extern const uint32_t DM_SERVICE_CONST;
DM_EXPORT extern const uint32_t DM_APP_CONST;

DM_EXPORT extern const char* DM_TAG_PEER_BUNDLE_NAME;
DM_EXPORT extern const char* DM_TAG_PEER_TOKENID;

#define DM_IDENTICAL_ACCOUNT_VAL 1
#define DM_SHARE_VAL 2
#define DM_LNN_VAL 3
#define DM_POINT_TO_POINT_VAL 256
#define DM_ACROSS_ACCOUNT_VAL 1282

typedef enum DmProfileState {
    DM_INACTIVE = 0,
    DM_ACTIVE = 1
} DmProfileState;

typedef struct {
    DmString pkgname;
    DmString localDeviceId;
    int32_t userId;
    DmString remoteDeviceIdHash;
} DmDiscoveryInfo;

typedef struct {
    DmString sessionKey;
    int32_t bindType;
    int32_t state;
    DmString trustDeviceId;
    int32_t bindLevel;
    int32_t authenticationType;
    DmString deviceIdHash;
    DmString extraData;
} DmAclInfo;

typedef struct {
    uint64_t requestTokenId;
    DmString requestBundleName;
    int32_t requestUserId;
    DmString requestAccountId;
    DmString requestDeviceId;
    int32_t requestTargetClass;
    DmString requestDeviceName;
    DmString requestCredentialId;
    int64_t requestSkTimeStamp;
    DmString requestExtraData;
} DmAccesser;

typedef struct {
    uint64_t trustTokenId;
    DmString trustBundleName;
    int32_t trustUserId;
    DmString trustAccountId;
    DmString trustDeviceId;
    int32_t trustTargetClass;
    DmString trustDeviceName;
    DmString trustCredentialId;
    int64_t trustSkTimeStamp;
    DmString trustExtraData;
} DmAccessee;

typedef struct {
    DmString udid;
    int32_t userId;
    DmString credId;
    DmString pkgName;
    DmVecInt64_t tokenIds;
} DmAclIdParam;

void DmAclIdParamInit(DmAclIdParam* param);

DM_VEC_DEFINE(DmAclIdParam);
DM_VEC_DEFINE(DmUserRemovedServiceInfo);

typedef struct {
    uint32_t bindType;
    DmVec_ProcessInfo processVec;
    DmVec_DmString credIdVec;
    int32_t leftAclNumber;
    int32_t peerUserId;
    bool hasLnnAcl;
    bool hasUserAcl;
    bool isNewVersion;
    DmVec_DmAclIdParam needDelAclInfos;
    DmVec_DmAclIdParam allLnnAclInfos;
    DmVec_DmAclIdParam allLeftAppOrSvrAclInfos;
    DmVec_DmAclIdParam allUserAclInfos;
} DmOfflineParam;

void DmOfflineParamInit(DmOfflineParam* param);

DM_VEC_DEFINE(DmOfflineParam);

typedef struct {
    DmString localUdid;
    int32_t preUserId;
    DmVec_DmString peerUdids;
} DmLocalUserRemovedInfo;

typedef struct {
    DmString peerUdid;
    int32_t peerUserId;
    DmVec_int localUserIds;
} DmRemoteUserRemovedInfo;

typedef struct {
    DmString version;
    DmVec_DmString aclHashList;
} DmAclHashItem;

DM_VEC_DEFINE(DmAclHashItem);

typedef struct {
    DmString peerUdid;
    int32_t peerUserId;
    int32_t localUserId;
} DmAuthOnceAclInfo;

DM_HMAP_DEFINE(DmAuthOnceAclInfo_int, DmAuthOnceAclInfo, int);
DM_SET_DEFINE(DmAuthOnceAclInfo);
DM_HMAP_DEFINE(DmString_DmAuthForm, DmString, DmAuthForm);
DM_MAP_DEFINE(DmString_DmOfflineParam, DmString, DmOfflineParam);

typedef struct DmDeviceProfileConnector DmDeviceProfileConnector;

DM_DECLARE_SINGLE_INSTANCE(DmDeviceProfileConnector);

DM_EXPORT int32_t DmDpConnectorGetAccessControlProfile(DmVecVoid* profiles);
DM_EXPORT uint32_t DmDpConnectorCheckBindType(const char* peerUdid, const char* localUdid);
DM_EXPORT bool DmDpConnectorIsLnnAcl(void* profile);

DM_EXPORT DmString DmShellProfileGetTrustDeviceId(void* profilePtr);
DM_EXPORT DmString DmShellProfileGetAccesserDeviceId(void* profilePtr);
DM_EXPORT DmString DmShellProfileGetAccesseeDeviceId(void* profilePtr);
DM_EXPORT int32_t DmShellProfileGetAccesserUserId(void* profilePtr);
DM_EXPORT int32_t DmShellProfileGetAccesseeUserId(void* profilePtr);
DM_EXPORT int32_t DmShellProfileGetStatus(void* profilePtr);
DM_EXPORT void DmShellProfileSetStatus(void* profilePtr, int32_t status);
DM_EXPORT uint32_t DmShellProfileGetBindLevel(void* profilePtr);
DM_EXPORT int32_t DmShellProfileGetBindType(void* profilePtr);
DM_EXPORT void DmShellDeleteAccessControlProfile(const char* trustDeviceId);

DM_EXPORT int32_t DmDpConnectorGetAllAclIncludeLnnAcl(DmVecVoid* profiles);
DM_EXPORT int32_t DmDpConnectorGetAclProfileByDeviceIdAndUserIdRemote(DmVecVoid* profiles,
    const char* deviceId, int32_t userId, const char* remoteDeviceId);

#ifdef __cplusplus
}
#endif

#endif
