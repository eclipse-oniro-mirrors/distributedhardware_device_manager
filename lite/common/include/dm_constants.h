/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef DM_CONSTANTS_H
#define DM_CONSTANTS_H

#include "dm_error_type.h"
#include "dm_container.h"

#ifndef DM_EXPORT
#define DM_EXPORT __attribute__((visibility("default")))
#endif

#define DM_PKG_NAME "ohos.distributedhardware.devicemanager"
#define DM_PKG_NAME_LITE "ohos.distributedhardware.devicemanager"
#define DM_ALL_PKGNAME "all"

#define DM_CAPABILITY_OSD "osdCapability"

#define DM_MAX_CONTAINER_SIZE 10000u
#define DM_MAX_TRUST_DEVICE_NUM 100

#define DM_PARAM_KEY_OS_TYPE "OS_TYPE"
#define DM_PARAM_KEY_OS_VERSION "OS_VERSION"

#endif
