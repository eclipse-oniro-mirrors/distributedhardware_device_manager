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


#include "discovery_manager_c.h"
#include <stdlib.h>
#include <string.h>
#include "securec.h"
#include "dm_log.h"
#include "dm_error_type.h"
#include "dm_constants.h"
#include "discovery_filter.h"
#include "softbus_listener_c.h"

DM_IMPLEMENT_SINGLE_INSTANCE(DiscoveryManager)

DM_MAP_IMPL(DmString_MultiUserDiscovery, DmString, MultiUserDiscovery, DmCmpDmString)
DM_MAP_IMPL(DmString_DiscoveryContext, DmString, DiscoveryContext, DmCmpDmString)

int32_t DmDiscoveryManagerInit(DiscoveryManager* mgr, void* softbusListener, void* listener)
{
    CHECK_NULL_RETURN(mgr, ERR_DM_FAILED);
    DmMutexInit(&mgr->locks);
    DmMutexInit(&mgr->subIdMapLocks);
    DmMutexInit(&mgr->timerLocks);
    DmMutexInit(&mgr->capabilityMapLocks);
    DmMutexInit(&mgr->multiUserDiscLocks);
    mgr->timer = NULL;
    mgr->softbusListener = softbusListener;
    mgr->listener = listener;
    DmMap_DmString_DmMap_uint16_uint16_Init(&mgr->pkgName2SubIdMap);
    DmMap_DmString_DiscoveryContext_Init(&mgr->discoveryContextMap);
    DmSetDmStringInit(&mgr->pkgNameSet);
    DmMap_DmString_DmString_Init(&mgr->capabilityMap);
    DmMap_DmString_MultiUserDiscovery_Init(&mgr->multiUserDiscMap);
    DmSet_uint16_t_Init(&mgr->randSubIdSet);
    LOGI("DiscoveryManager init.");
    return DM_OK;
}
