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
#ifndef OHOS_DM_DEVICEPROFILE_CONNECTOR_3RD_REFACTOR_H
#define OHOS_DM_DEVICEPROFILE_CONNECTOR_3RD_REFACTOR_H

#include <algorithm>
#include <map>
#include <string>
#include <unordered_set>
#include "access_control_profile.h"
#include "device_manager_data_struct_3rd.h"
#include "dm_single_instance_3rd.h"
#include "i_dp_inited_callback.h"
#include "json_object.h"
#include "local_service_info.h"
#include "parameter.h"
#include "service_info.h"
#include "single_instance.h"
#include "trusted_device_info.h"

#ifndef DM_EXPORT
#define DM_EXPORT __attribute__ ((visibility ("default")))
#endif

namespace OHOS {
namespace DistributedHardware {

class IDeviceProfileConnectorRefactor {
public:
    virtual ~IDeviceProfileConnectorRefactor() = default;
};

class DeviceProfileConnector3rdRefactor : public IDeviceProfileConnectorRefactor {
    DM_DECLARE_SINGLE_INSTANCE_3RD(DeviceProfileConnector3rdRefactor);
public:
    DM_EXPORT int32_t DeleteSessionKey(int32_t userId, int32_t sessionKeyId);
    DM_EXPORT int32_t PutSessionKey(int32_t userId, const std::vector<unsigned char> &sessionKeyArray,
        int32_t &sessionKeyId);
    DM_EXPORT int32_t GetSessionKey(int32_t userId, int32_t sessionKeyId,
        std::vector<unsigned char> &sessionKeyArray);
};

DM_EXPORT extern "C" IDeviceProfileConnectorRefactor *CreateDpConnectorRefactorInstance();
using CreateDpConnectorRefactorFuncPtr = IDeviceProfileConnectorRefactor *(*)(void);

} // namespace DistributedHardware
} // namespace OHOS
#endif
