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


#include "dm_device_info_c.h"
#include <stdlib.h>
#include <string.h>
#include "securec.h"

DM_VEC_IMPL(DmDeviceInfo)
DM_VEC_IMPL(DmDeviceBasicInfo)
DM_VEC_IMPL(DMLocalServiceInfo)
DM_VEC_IMPL(DmServiceInfo)
DM_VEC_IMPL(DmRegisterServiceInfo)

int DmProcessInfoCmp(ProcessInfo a, ProcessInfo b)
{
    return a.userId != b.userId;
}

DM_SET_IMPL(ProcessInfo, DmProcessInfoCmp)
DM_MAP_IMPL(int_DmSet_ProcessInfo, int, DmSet_ProcessInfo, DmCmpInt)

void DmSet_ProcessInfo_Clear(DmSet_ProcessInfo* s)
{
    for (int i = 0; i < s->size; i++) {
        DmProcessInfoDestroy(&s->data[i]);
    }
    s->size = 0;
}
void DmSet_ProcessInfo_Destroy(DmSet_ProcessInfo* s)
{
    DmSet_ProcessInfo_Clear(s);
    free(s->data);
    s->data = NULL;
    s->size = 0;
    s->cap = 0;
}

void DmMap_int_DmSet_ProcessInfo_Clear(DmMap_int_DmSet_ProcessInfo* m)
{
    for (int i = 0; i < m->size; i++) {
        DmSet_ProcessInfo_Destroy(&m->data[i].val);
    }
    m->size = 0;
}
void DmMap_int_DmSet_ProcessInfo_Destroy(DmMap_int_DmSet_ProcessInfo* m)
{
    DmMap_int_DmSet_ProcessInfo_Clear(m);
    free(m->data);
    m->data = NULL;
    m->size = 0;
    m->cap = 0;
}

void DmDeviceInfoInit(DmDeviceInfo* info)
{
    (void)memset_s(info->deviceId, DM_MAX_DEVICE_ID_LEN, 0, DM_MAX_DEVICE_ID_LEN);
    (void)memset_s(info->deviceName, DM_MAX_DEVICE_NAME_LEN, 0, DM_MAX_DEVICE_NAME_LEN);
    info->deviceTypeId = DEVICE_TYPE_UNKNOWN;
    (void)memset_s(info->networkId, DM_MAX_DEVICE_ID_LEN, 0, DM_MAX_DEVICE_ID_LEN);
    info->range = 0;
    info->networkType = 0;
    info->authForm = DM_AUTH_FORM_INVALID_TYPE;
    info->extraData = DmStringCreateEmpty();
}

void DmDeviceInfoDestroy(DmDeviceInfo* info)
{
    DmStringDestroy(&info->extraData);
}

void DmAccessCallerInit(DmAccessCaller* caller)
{
    caller->accountId = DmStringCreateEmpty();
    caller->pkgName = DmStringCreateEmpty();
    caller->networkId = DmStringCreateEmpty();
    caller->userId = 0;
    caller->tokenId = 0;
    caller->extra = DmStringCreateEmpty();
}

void DmAccessCallerDestroy(DmAccessCaller* caller)
{
    DmStringDestroy(&caller->accountId);
    DmStringDestroy(&caller->pkgName);
    DmStringDestroy(&caller->networkId);
    DmStringDestroy(&caller->extra);
}

void DmAccessCalleeInit(DmAccessCallee* callee)
{
    callee->accountId = DmStringCreateEmpty();
    callee->networkId = DmStringCreateEmpty();
    callee->peerId = DmStringCreateEmpty();
    callee->pkgName = DmStringCreateEmpty();
    callee->userId = 0;
    callee->tokenId = 0;
    callee->extra = DmStringCreateEmpty();
}

void DmAccessCalleeDestroy(DmAccessCallee* callee)
{
    DmStringDestroy(&callee->accountId);
    DmStringDestroy(&callee->networkId);
    DmStringDestroy(&callee->peerId);
    DmStringDestroy(&callee->pkgName);
    DmStringDestroy(&callee->extra);
}

void DmProcessInfoInit(ProcessInfo* info)
{
    info->userId = 0;
    info->pkgName = DmStringCreateEmpty();
    info->tokenId = 0;
}

void DmProcessInfoDestroy(ProcessInfo* info)
{
    DmStringDestroy(&info->pkgName);
}

void DmServiceInfoStructInit(ServiceInfo* info)
{
    info->serviceId = 0;
    info->serviceType = DmStringCreateEmpty();
    info->serviceName = DmStringCreateEmpty();
    info->serviceDisplayName = DmStringCreateEmpty();
}

void DmServiceInfoStructDestroy(ServiceInfo* info)
{
    DmStringDestroy(&info->serviceType);
    DmStringDestroy(&info->serviceName);
    DmStringDestroy(&info->serviceDisplayName);
}
