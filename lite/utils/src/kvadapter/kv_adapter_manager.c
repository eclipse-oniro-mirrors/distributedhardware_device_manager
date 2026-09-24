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


#include "kv_adapter_manager.h"

#include <stdlib.h>
#include <string.h>

#include "dm_anonymous.h"
#include "dm_error_type.h"
#include "dm_log.h"

#define DM_KV_STORE_PREFIX "DM2_"
#define DM_KV_STORE_FREEZE_PREFIX "anti_ddos_local_"
#define DM_DB_KEY_DELIMITER "###"
#define DM_KV_STORE_REFRESH_TIME (24 * 60 * 60)
#define DM_MAX_SUPPORTED_EXIST_TIME (3 * 24 * 60 * 60)
#define DM_OSTYPE_PREFIX "ostype"
#define DM_UDID_PREFIX "udid"
const int DM_BASE_TEN = 10;

DM_IMPLEMENT_SINGLE_INSTANCE(KVAdapterManager);

DM_EXPORT int32_t DmKvAdapterManagerInit(void)
{
    KVAdapterManager* mgr = KVAdapterManagerGetInstance();
    DmMutexLock(&mgr->idCacheMapMtx);
    (void)DmHmap_DmString_DmString_Clear(&mgr->idCacheMap);
    DmMutexUnlock(&mgr->idCacheMapMtx);
    int32_t ret = DM_OK;
    DmMutexLock(&mgr->kvAdapterMtx);
    if (mgr->kvAdapter == NULL) {
        mgr->kvAdapter = DmKvAdapterCreate();
        ret = DmKvAdapterInit(mgr->kvAdapter);
    }
    DmMutexUnlock(&mgr->kvAdapterMtx);
    return ret;
}

DM_EXPORT void DmKvAdapterManagerUninit(void)
{
    KVAdapterManager* mgr = KVAdapterManagerGetInstance();
    DmMutexLock(&mgr->kvAdapterMtx);
    if (mgr->kvAdapter == NULL) {
        DmMutexUnlock(&mgr->kvAdapterMtx);
        return;
    }
    DmKvAdapterUninit(mgr->kvAdapter);
    DmKvAdapterDestroy(mgr->kvAdapter);
    mgr->kvAdapter = NULL;
    DmMutexUnlock(&mgr->kvAdapterMtx);
}

DM_EXPORT void DmKvAdapterManagerReinit(void)
{
    KVAdapterManager* mgr = KVAdapterManagerGetInstance();
    DmMutexLock(&mgr->kvAdapterMtx);
    if (mgr->kvAdapter == NULL) {
        DmMutexUnlock(&mgr->kvAdapterMtx);
        return;
    }
    DmKvAdapterReinit(mgr->kvAdapter);
    DmMutexUnlock(&mgr->kvAdapterMtx);
}

DM_EXPORT int32_t DmKvAdapterManagerGet(const char* key, DmKVValue* value)
{
    KVAdapterManager* mgr = KVAdapterManagerGetInstance();
    DmString dmKey = DmStringCreate(DM_KV_STORE_PREFIX);
    DmStringAppend(&dmKey, key);
    DmMutexLock(&mgr->idCacheMapMtx);
    DmString* idIter = DmHmap_DmString_DmString_Find(&mgr->idCacheMap, dmKey);
    if (idIter != NULL) {
        DmMutexUnlock(&mgr->idCacheMapMtx);
        DmStringDestroy(&dmKey);
        return DM_OK;
    }
    DmMutexUnlock(&mgr->idCacheMapMtx);
    DmString valueStr = DmStringCreateEmpty();
    DmMutexLock(&mgr->kvAdapterMtx);
    if (mgr->kvAdapter == NULL) {
        DmMutexUnlock(&mgr->kvAdapterMtx);
        DmStringDestroy(&dmKey);
        return ERR_DM_POINT_NULL;
    }
    if (DmKvAdapterGet(mgr->kvAdapter, DmStringCstr(&dmKey), &valueStr) != DM_OK) {
        DmString anonyDmKey = DmGetAnonyString(&dmKey);
        LOGE("kv value failed, dmKey: %{public}s", DmStringCstr(&anonyDmKey));
        DmStringDestroy(&anonyDmKey);
        DmMutexUnlock(&mgr->kvAdapterMtx);
        DmStringDestroy(&dmKey);
        return ERR_DM_FAILED;
    }
    DmMutexUnlock(&mgr->kvAdapterMtx);
    DmConvertJsonToKvValue(&valueStr, value);
    DmMutexLock(&mgr->idCacheMapMtx);
    DmString prefixKey = DmStringCreate(DM_KV_STORE_PREFIX);
    DmStringAppend(&prefixKey, DmStringCstr(&value->appID));
    DmStringAppend(&prefixKey, DM_DB_KEY_DELIMITER);
    DmStringAppend(&prefixKey, DmStringCstr(&value->udidHash));
    (void)DmHmap_DmString_DmString_Insert(&mgr->idCacheMap, DmStringCopy(&dmKey), DmStringCreate(""));
    (void)DmHmap_DmString_DmString_Insert(&mgr->idCacheMap, DmStringCopy(&prefixKey), DmStringCreate(""));
    DmMutexUnlock(&mgr->idCacheMapMtx);
    DmStringDestroy(&dmKey);
    DmStringDestroy(&prefixKey);
    DmStringDestroy(&valueStr);
    return DM_OK;
}
