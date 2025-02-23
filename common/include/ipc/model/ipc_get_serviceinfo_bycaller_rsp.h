/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DM_IPC_GET_SERVICEINFO_BYCALLER_RSP_H
#define OHOS_DM_IPC_GET_SERVICEINFO_BYCALLER_RSP_H

#include <vector>

#include "dm_device_info.h"
#include "ipc_req.h"

namespace OHOS {
namespace DistributedHardware {
class IpcGetServiceInfoByCallerRsp : public IpcRsp {
    DECLARE_IPC_MODEL(IpcGetServiceInfoByCallerRsp);

public:
    const std::vector<DMServiceInfo>& GetServiceInfos() const
    {
        return serviceInfos_;
    }

    void SetServiceInfos(const std::vector<DMServiceInfo> &infos)
    {
        serviceInfos_ = infos;
    }

private:
    std::vector<DMServiceInfo> serviceInfos_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_IPC_GET_SERVICEINFO_BYCALLER_RSP_H
