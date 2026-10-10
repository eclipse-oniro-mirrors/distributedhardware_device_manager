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


#include "device_manager_service.h"
#include <stdlib.h>
#include <string.h>
#include "securec.h"
#include "dm_log.h"
#include "dm_error_type.h"
#include "dm_constants.h"

#include "softbus_listener_c.h"
#include "deviceprofile_connector.h"
#include "softbus_bus_center.h"
#include "discovery_manager_c.h"
#include "device_manager_service_listener.h"
#include "dm_local_acl_profile.h"
#include "permission_manager.h"
#include "device_auth.h"

#define DM_PERMISSION_LEVEL_MONITOR 2

DM_IMPLEMENT_SINGLE_INSTANCE(DeviceManagerService)

static DeviceManagerServiceListener g_serviceListener;

int32_t DmServiceInit(void)
{
    LOGI("DeviceManagerService init lite");
    DiscoveryManager* discMgr = DiscoveryManagerGetInstance();
    DmDiscoveryManagerInit(discMgr, NULL, &g_serviceListener);
    DmServiceListenerInit(&g_serviceListener);
    DmAclStoreInit();
    LOGI("DiscoveryManager, ServiceListener, ACL store initialized");
    return DM_OK;
}

int32_t DmServiceGetTrustedDeviceList(const DmString* pkgName, const DmString* extra, DmVec_DmDeviceInfo* deviceList)
{
    (void)extra;
    CHECK_NULL_RETURN(pkgName, ERR_DM_FAILED);
    DmVec_DmDeviceInfo onlineList;
    DmVec_DmDeviceInfo_Init(&onlineList);
    int32_t ret = DmSoftbusListenerGetTrustedDeviceList(&onlineList);
    if (ret != DM_OK || DmVec_DmDeviceInfo_Size(&onlineList) == 0) {
        DmVec_DmDeviceInfo_Destroy(&onlineList);
        return ret;
    }
    bool isOnlyShowNetworkId = !(DmPermissionCheckAccessService(pkgName) ||
        DmPermissionCheckDataSync(pkgName));
    for (int32_t i = 0; i < DmVec_DmDeviceInfo_Size(&onlineList); i++) {
        DmDeviceInfo* dev = DmVec_DmDeviceInfo_At(&onlineList, i);
        if (isOnlyShowNetworkId) {
            DmDeviceInfo tempInfo;
            (void)memset_s(&tempInfo, sizeof(DmDeviceInfo), 0, sizeof(DmDeviceInfo));
            (void)strncpy_s(tempInfo.networkId, sizeof(tempInfo.networkId),
                dev->networkId, sizeof(tempInfo.networkId) - 1);
            DmVec_DmDeviceInfo_Push(deviceList, tempInfo);
        } else {
            DmVec_DmDeviceInfo_Push(deviceList, *dev);
        }
    }
    DmVec_DmDeviceInfo_Destroy(&onlineList);
    LOGI("GetTrustedDeviceList trusted=%d", DmVec_DmDeviceInfo_Size(deviceList));
    return DM_OK;
}

int32_t DmServiceGetLocalDeviceInfo(DmDeviceInfo* info)
{
    CHECK_NULL_RETURN(info, ERR_DM_FAILED);
    return DmSoftbusListenerGetLocalDeviceInfo(info);
}

int32_t DmServiceGetDeviceInfo(const DmString* networkId, DmDeviceInfo* info)
{
    CHECK_NULL_RETURN(networkId, ERR_DM_FAILED);
    return DmSoftbusListenerGetDeviceInfo(networkId, info);
}

int32_t DmServicePublishDeviceDiscovery(const DmString* pkgName, const DmPublishInfo* publishInfo)
{
    CHECK_NULL_RETURN(pkgName, ERR_DM_FAILED);
    CHECK_NULL_RETURN(publishInfo, ERR_DM_FAILED);
    const char* reqCap = publishInfo->capability;
    bool capEmpty = (reqCap == NULL || reqCap[0] == '\0');
    DmString capability = DmStringCreate(capEmpty ? DM_CAPABILITY_OSD : reqCap);
    if (capEmpty) {
        LOGW("PublishDeviceDiscovery empty capability from caller, fallback to %s", DM_CAPABILITY_OSD);
    }
    LOGW("PublishDeviceDiscovery publishId=%d mode=%d medium=%d capability=%s",
         publishInfo->publishId, publishInfo->mode, publishInfo->medium, DmStringCstr(&capability));
    int32_t ret = DmSoftbusListenerPublishSoftbusLnn(publishInfo, &capability, NULL);
    DmStringDestroy(&capability);
    return ret;
}

int32_t DmServiceUnpublishDeviceDiscovery(const DmString* pkgName, int32_t publishId)
{
    CHECK_NULL_RETURN(pkgName, ERR_DM_FAILED);
    return DmSoftbusListenerStopPublishSoftbusLnn(publishId);
}

int32_t DmServiceSetLocalDisplayNameToSoftbus(const DmString* displayName)
{
    CHECK_NULL_RETURN(displayName, ERR_DM_FAILED);
    return DmSoftbusListenerSetLocalDisplayName(displayName);
}
