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


#ifndef DM_DISCOVERY_MANAGER_C_H
#define DM_DISCOVERY_MANAGER_C_H

#include <stdint.h>
#include <stdbool.h>
#include "dm_container.h"
#include "dm_device_info_c.h"
#include "dm_thread.h"
#include "discovery_filter.h"
#include "dm_single_instance.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef struct DiscoveryContext {
    DmString pkgName;
    DmString extra;
    uint16_t subscribeId;
    DmString filterOp;
    DmVec_DmDeviceFilters filters;
} DiscoveryContext;

typedef struct MultiUserDiscovery {
    DmString pkgName;
    int32_t userId;
    uint32_t tokenId;
} MultiUserDiscovery;

DM_MAP_DEFINE(DmString_MultiUserDiscovery, DmString, MultiUserDiscovery);
DM_MAP_DEFINE(DmString_DiscoveryContext, DmString, DiscoveryContext);

typedef struct DiscoveryManager {
    DmMutex locks;
    DmMutex subIdMapLocks;
    DmMutex timerLocks;
    void* timer;
    DmMap_DmString_DmMap_uint16_uint16 pkgName2SubIdMap;
    void* softbusListener;
    void* listener;
    DmMap_DmString_DiscoveryContext discoveryContextMap;
    DmSetDmString pkgNameSet;
    DmMap_DmString_DmString capabilityMap;
    DmMutex capabilityMapLocks;
    DmMutex multiUserDiscLocks;
    DmMap_DmString_MultiUserDiscovery multiUserDiscMap;
    DmSet_uint16_t randSubIdSet;
} DiscoveryManager;

DM_DECLARE_SINGLE_INSTANCE(DiscoveryManager);

int32_t DmDiscoveryManagerInit(DiscoveryManager* mgr, void* softbusListener, void* listener);


#ifdef __cplusplus
}
#endif

#endif
