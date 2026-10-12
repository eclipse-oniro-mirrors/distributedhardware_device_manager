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


#include "ipc_cmd_register.h"
#include "device_manager_ipc_interface_code.h"
#include "dm_error_type.h"
#include "dm_log.h"
#include "dm_container.h"


DM_IMPLEMENT_SINGLE_INSTANCE(DmIpcCmdRegister)

void DmIpcCmdRegisterInit(DmIpcCmdRegister* inst)
{
    DmMutexInit(&inst->setIpcRequestFuncMapLock);
    DmHmap_int_DmVoidPtr_Init(&inst->setIpcRequestFuncMap);
    DmMutexInit(&inst->readResponseFuncMapLock);
    DmHmap_int_DmVoidPtr_Init(&inst->readResponseFuncMap);
    DmMutexInit(&inst->onIpcCmdFuncMapLock);
    DmHmap_int_DmVoidPtr_Init(&inst->onIpcCmdFuncMap);
}

static bool dm_ipc_cmd_register_initialized = false;
static void DmIpcCmdRegisterEnsureInit(DmIpcCmdRegister* inst)
{
    if (!dm_ipc_cmd_register_initialized) {
        DmIpcCmdRegisterInit(inst);
        dm_ipc_cmd_register_initialized = true;
    }
}

void DmIpcCmdRegisterRegisterCmdProcessFunc(int32_t cmdCode, DmOnIpcCmdFunc func)
{
    DmIpcCmdRegister* inst = DmIpcCmdRegisterGetInstance();
    DmIpcCmdRegisterEnsureInit(inst);
    DmMutexLock(&inst->onIpcCmdFuncMapLock);
    DmHmap_int_DmVoidPtr_Insert(&inst->onIpcCmdFuncMap, cmdCode, (DmVoidPtr)func);
    DmMutexUnlock(&inst->onIpcCmdFuncMapLock);
}

int32_t DmIpcCmdRegisterOnIpcCmd(int32_t cmdCode, void* data, void* reply)
{
    if (cmdCode < 0 || cmdCode >= DM_IPC_MSG_BUTT) {
        LOGE("cmdCode param invalid!");
        return ERR_DM_UNSUPPORTED_IPC_COMMAND;
    }
    DmIpcCmdRegister* inst = DmIpcCmdRegisterGetInstance();
    DmOnIpcCmdFunc ptr = NULL;
    {
        DmMutexLock(&inst->onIpcCmdFuncMapLock);
        DmVoidPtr* found = DmHmap_int_DmVoidPtr_Find(&inst->onIpcCmdFuncMap, cmdCode);
        if (found == NULL) {
            DmMutexUnlock(&inst->onIpcCmdFuncMapLock);
            LOGE("cmdCode:%{public}d not register OnIpcCmdFunc", cmdCode);
            return ERR_DM_UNSUPPORTED_IPC_COMMAND;
        }
        ptr = (DmOnIpcCmdFunc)(*found);
        DmMutexUnlock(&inst->onIpcCmdFuncMapLock);
        if (ptr == NULL) {
            LOGE("onIpcCmdMapIter->second is null");
            return ERR_DM_POINT_NULL;
        }
    }
    return ptr(cmdCode, data, reply);
}

int32_t DmIpcCmdRegisterOnRemoteRequest(int32_t cmdCode, void* data, void* reply)
{
    return DmIpcCmdRegisterOnIpcCmd(cmdCode, data, reply);
}
