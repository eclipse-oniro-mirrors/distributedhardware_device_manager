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


#ifndef DM_SHELL_FUNCTIONS_H
#define DM_SHELL_FUNCTIONS_H

#include "deviceprofile_connector.h"
#include "multiple_user_connector.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t DmShellGetAccessControlProfileByUserId(DmVecVoid* profiles, int32_t userId);
int32_t DmShellGetAclProfileByUserId(DmVecVoid* profiles, const char* localUdid,
    int32_t userId, const char* remoteUdid);
uint32_t DmShellGetAuthFormPriority(void* profilePtr, const char* peerUdid, const char* localUdid);
bool DmShellIsLnnAcl(void* profilePtr);
int32_t DmShellGetForegroundUserIds(DmVec_int* userVec);

int32_t DmShellGetCurrentAccountUserId(void);
int32_t DmShellQueryActiveOsAccountIds(int32_t* userId);
int32_t DmShellCheckOsAccountConstraintEnabled(int32_t userId, const char* constraint, bool* isEnabled);
DmString DmShellGetOhosAccountId(void);
DmString DmShellGetOhosAccountIdByUserId(int32_t userId);
DmString DmShellGetOhosAccountNameByUserId(int32_t userId);
DmString DmShellGetOhosAccountName(void);
void DmShellGetCallingTokenId(uint32_t* tokenId);
void DmShellGetCallerUserId(int32_t* userId);
int32_t DmShellGetBackgroundUserIds(DmVec_int* userIdVec);
int32_t DmShellGetAllUserIds(DmVec_int* userIdVec);
DmString DmShellGetAccountNickName(int32_t userId);
bool DmShellIsUserUnlocked(int32_t userId);
void DmShellGetForegroundOsAccountLocalIdByDisplayId(int32_t displayId, int32_t* userId);

#ifdef __cplusplus
}
#endif

#endif
