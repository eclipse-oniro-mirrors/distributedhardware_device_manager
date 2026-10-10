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


#include "deviceprofile_connector.h"
#include "dm_anonymous.h"
#include "dm_constants.h"

DM_VEC_IMPL(DmAclIdParam)
DM_VEC_IMPL(DmUserRemovedServiceInfo)
DM_VEC_IMPL(DmAclHashItem)
DM_HMAP_IMPL(DmString_DmAuthForm, DmString, DmAuthForm, DmHashDmString, DmCmpDmString)
static int DmCmp_Dmauthonceaclinfo(DmAuthOnceAclInfo a, DmAuthOnceAclInfo b)
{
    if (a.localUserId != b.localUserId) {
        return (a.localUserId > b.localUserId) - (a.localUserId < b.localUserId);
    }
    if (a.peerUserId != b.peerUserId) {
        return (a.peerUserId > b.peerUserId) - (a.peerUserId < b.peerUserId);
    }
    return DmStringCmp(&a.peerUdid, &b.peerUdid);
}
DM_SET_IMPL(DmAuthOnceAclInfo, DmCmp_Dmauthonceaclinfo)
DM_MAP_IMPL(DmString_DmOfflineParam, DmString, DmOfflineParam, DmCmpDmString)
#include "dm_log.h"
#include "multiple_user_connector.h"
#include "json_object.h"
#include "dm_shell_functions.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const uint32_t DM_INVALIED_TYPE = 0;
const uint32_t DM_APP_PEER_TO_PEER_TYPE = 1;
const uint32_t DM_APP_ACROSS_ACCOUNT_TYPE = 2;
const uint32_t DM_SERVICE_PEER_TO_PEER_TYPE = 3;
const uint32_t DM_SERVICE_ACROSS_ACCOUNT_TYPE = 4;
const uint32_t DM_SHARE_TYPE = 5;
const uint32_t DM_DEVICE_PEER_TO_PEER_TYPE = 6;
const uint32_t DM_DEVICE_ACROSS_ACCOUNT_TYPE = 7;
const uint32_t DM_IDENTICAL_ACCOUNT_TYPE = 8;
const uint32_t DM_DM_INVALIED_TYPE = 2048;
const uint32_t DM_SERVICE_CONST = 2;
const uint32_t DM_APP_CONST = 3;
const uint32_t DM_BIND_LEVEL_USER = 1;
const char* DM_TAG_PEER_BUNDLE_NAME = "peerBundleName";
const char* DM_TAG_PEER_TOKENID = "peerTokenId";

typedef enum {
    DM_DEVICE_PEER_TO_PEER_BIND_TYPE = 3,
    DM_DEVICE_ACROSS_ACCOUNT_BIND_TYPE = 4,
    DM_IDENTICAL_ACCOUNT_BIND_TYPE = 5
} DmDevBindType;

void DmAclIdParamInit(DmAclIdParam* param)
{
    param->udid = DmStringCreateEmpty();
    param->userId = 0;
    param->credId = DmStringCreateEmpty();
    param->pkgName = DmStringCreateEmpty();
    DmVecInt64_t_Init(&param->tokenIds);
}

void DmOfflineParamInit(DmOfflineParam* param)
{
    param->bindType = 0;
    DmVec_ProcessInfo_Init(&param->processVec);
    DmVec_DmString_Init(&param->credIdVec);
    param->leftAclNumber = 0;
    param->peerUserId = 0;
    param->hasLnnAcl = false;
    param->hasUserAcl = false;
    param->isNewVersion = true;
    DmVec_DmAclIdParam_Init(&param->needDelAclInfos);
    DmVec_DmAclIdParam_Init(&param->allLnnAclInfos);
    DmVec_DmAclIdParam_Init(&param->allLeftAppOrSvrAclInfos);
    DmVec_DmAclIdParam_Init(&param->allUserAclInfos);
}

struct DmDeviceProfileConnector {
    void* cppHandle;
};

DM_IMPLEMENT_SINGLE_INSTANCE(DmDeviceProfileConnector)

int32_t DmDpConnectorGetAccessControlProfile(DmVecVoid* profiles)
{
    int32_t userId = DmMultipleUserGetCurrentAccountUserId();
    return DmShellGetAccessControlProfileByUserId(profiles, userId);
}

uint32_t DmDpConnectorCheckBindType(const char* peerUdid, const char* localUdid)
{
    DmVecVoid filterProfiles;
    DmVecVoidInit(&filterProfiles);
    DmShellGetAclProfileByUserId(&filterProfiles, localUdid,
        DmMultipleUserGetFirstForegroundUserId(), peerUdid);
    uint32_t highestPriority = DM_INVALIED_TYPE;
    for (int i = 0; i < DmVecVoidSize(&filterProfiles); i++) {
        void** item = DmVecVoidAt(&filterProfiles, i);
        if (item == NULL) {
            continue;
        }
        bool isLnn = DmDpConnectorIsLnnAcl(*item);
        DmString trustDevId = DmShellProfileGetTrustDeviceId(*item);
        if (isLnn || DmStringCmpCstr(&trustDevId, peerUdid) != 0) {
            DmStringDestroy(&trustDevId);
            continue;
        }
        uint32_t priority = DmShellGetAuthFormPriority(*item, peerUdid, localUdid);
        if (priority > highestPriority) {
            highestPriority = priority;
        }
        DmStringDestroy(&trustDevId);
    }
    DmVecVoidDestroy(&filterProfiles);
    return highestPriority;
}

bool DmDpConnectorIsLnnAcl(void* profilePtr)
{
    return DmShellIsLnnAcl(profilePtr);
}

void DmHmap_DmString_DmAuthForm_Clear(DmHmap_DmString_DmAuthForm* m)
{
    for (int i = 0; i < m->cap; i++) {
        if (m->data[i].state == 1) {
            DmStringDestroy(&m->data[i].key);
        }
    }
    m->size = 0;
}

void DmHmap_DmString_DmAuthForm_Destroy(DmHmap_DmString_DmAuthForm* m)
{
    DmHmap_DmString_DmAuthForm_Clear(m);
    free(m->data);
    m->data = NULL;
    m->size = 0;
    m->cap = 0;
}
