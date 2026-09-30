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


#include "dm_crypto.h"
#include "deviceprofile_connector.h"
#include "dm_shell_functions.h"
#include "dm_log.h"
#include "dm_error_type.h"
#include "dm_container.h"
#include "dm_constants.h"
#include "dm_local_acl_profile.h"
#include "json_object.h"
#include "cJSON.h"
#include "securec.h"
#include <stdlib.h>
#include <string.h>

#define DM_AUTH_PRIORITY_IDENTICAL_ACCOUNT 8
#define DM_AUTH_PRIORITY_SHARE 5
#define DM_AUTH_PRIORITY_P2P_USER 6
#define DM_AUTH_PRIORITY_P2P_SERVICE 4
#define DM_AUTH_PRIORITY_P2P_APP 3
#define DM_AUTH_PRIORITY_ACROSS_SERVICE 2
#define DM_AUTH_PRIORITY_ACROSS_APP 1

int32_t DmShellGetAccessControlProfileByUserId(DmVecVoid* profiles, int32_t userId)
{
    return DmAclStoreGetAll(profiles);
}

int32_t DmShellGetAclProfileByUserId(DmVecVoid* profiles, const char* localUdid,
    int32_t userId, const char* remoteUdid)
{
    return DmAclStoreGetByUdid(profiles, localUdid, userId, remoteUdid);
}

DmString DmShellProfileGetTrustDeviceId(void* profilePtr)
{
    if (profilePtr == NULL) {
        return DmStringCreateEmpty();
    }
    DmLocalAclProfile* p = (DmLocalAclProfile*)profilePtr;
    return DmStringCreate(DmStringCstr(&p->trustDeviceId));
}

uint32_t DmShellGetAuthFormPriority(void* profilePtr, const char* peerUdid, const char* localUdid)
{
    if (profilePtr == NULL) {
        return 0;
    }
    DmLocalAclProfile* p = (DmLocalAclProfile*)profilePtr;
    int32_t bindType = p->bindType;
    uint32_t bindLevel = p->bindLevel;
    if (bindType == DM_IDENTICAL_ACCOUNT_VAL) {
        return DM_AUTH_PRIORITY_IDENTICAL_ACCOUNT;
    }
    if (bindType == DM_SHARE_VAL) {
        return DM_AUTH_PRIORITY_SHARE;
    }
    if (bindType == DM_POINT_TO_POINT_VAL) {
        if (bindLevel == DM_BIND_LEVEL_USER) {
            return DM_AUTH_PRIORITY_P2P_USER;
        }
        if (bindLevel == DM_SERVICE_CONST) {
            return DM_AUTH_PRIORITY_P2P_SERVICE;
        }
        if (bindLevel == DM_APP_CONST) {
            return DM_AUTH_PRIORITY_P2P_APP;
        }
    }
    if (bindType == DM_ACROSS_ACCOUNT_VAL) {
        if (bindLevel == DM_SERVICE_CONST) {
            return DM_AUTH_PRIORITY_ACROSS_SERVICE;
        }
        if (bindLevel == DM_APP_CONST) {
            return DM_AUTH_PRIORITY_ACROSS_APP;
        }
    }
    return 0;
}

int32_t DmShellProfileGetStatus(void* profilePtr)
{
    if (profilePtr == NULL) {
        return DM_INACTIVE;
    }
    return DM_ACTIVE;
}

int32_t DmShellProfileGetBindType(void* profilePtr)
{
    if (profilePtr == NULL) {
        return 0;
    }
    return ((DmLocalAclProfile*)profilePtr)->bindType;
}

uint32_t DmShellProfileGetBindLevel(void* profilePtr)
{
    if (profilePtr == NULL) {
        return 0;
    }
    return ((DmLocalAclProfile*)profilePtr)->bindLevel;
}

DmString DmShellProfileGetAccesserDeviceId(void* profilePtr)
{
    if (profilePtr == NULL) {
        return DmStringCreateEmpty();
    }
    return DmStringCreate(DmStringCstr(&((DmLocalAclProfile*)profilePtr)->accesser.deviceId));
}

int32_t DmShellProfileGetAccesserUserId(void* profilePtr)
{
    if (profilePtr == NULL) {
        return 0;
    }
    return ((DmLocalAclProfile*)profilePtr)->accesser.userId;
}

DmString DmShellProfileGetAccesseeDeviceId(void* profilePtr)
{
    if (profilePtr == NULL) {
        return DmStringCreateEmpty();
    }
    return DmStringCreate(DmStringCstr(&((DmLocalAclProfile*)profilePtr)->accessee.deviceId));
}

int32_t DmShellProfileGetAccesseeUserId(void* profilePtr)
{
    if (profilePtr == NULL) {
        return 0;
    }
    return ((DmLocalAclProfile*)profilePtr)->accessee.userId;
}

void DmShellProfileSetStatus(void* profilePtr, int32_t status)
{
    (void)profilePtr;
    (void)status;
}

bool DmShellIsLnnAcl(void* profilePtr)
{
    (void)profilePtr;
    return false;
}

int32_t DmShellGetForegroundUserIds(DmVec_int* userVec)
{
    if (userVec == NULL) {
        return ERR_DM_INPUT_PARA_INVALID;
    }
    DmVec_int_Push(userVec, 0);
    return 0;
}

int32_t DmDpConnectorGetAllAclIncludeLnnAcl(DmVecVoid* profiles)
{
    return DmAclStoreGetAll(profiles);
}

int32_t DmDpConnectorGetAclProfileByDeviceIdAndUserIdRemote(DmVecVoid* profiles,
    const char* deviceId, int32_t userId, const char* remoteDeviceId)
{
    return DmAclStoreGetByUdid(profiles, deviceId, userId, remoteDeviceId);
}

void DmShellDeleteAccessControlProfile(const char* trustDeviceId)
{
    if (trustDeviceId == NULL) {
        return;
    }
    DmVecVoid profiles;
    DmVecVoidInit(&profiles);
    DmAclStoreGetAll(&profiles);
    for (int i = 0; i < DmVecVoidSize(&profiles); i++) {
        DmLocalAclProfile* p = (DmLocalAclProfile*)*DmVecVoidAt(&profiles, i);
        if (p == NULL) {
            continue;
        }
        if (strcmp(DmStringCstr(&p->trustDeviceId), trustDeviceId) == 0) {
            char key[32];
            DmAclKeyFromProfile(key, sizeof(key), p);
            DmAclStoreDeleteByKey(key);
        }
        DmLocalAclProfileDelete(p);
        profiles.data[i] = NULL;
    }
    free(profiles.data);
}
