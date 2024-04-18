/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DM_IPC_PERMISSION_REQ_H
#define OHOS_DM_IPC_PERMISSION_REQ_H

#include "ipc_req.h"

namespace OHOS {
namespace DistributedHardware {
class IpcPermissionReq : public IpcReq {
    DECLARE_IPC_MODEL(IpcPermissionReq);

public:
    /**
     * @tc.name: IpcPermissionReq::GetPublishId
     * @tc.desc: Get PublishId of the Ipc Notify Publish Result Request
     * @tc.type: FUNC
     */
    int32_t GetPermissionLevel() const
    {
        return permissionLevel_;
    }

    /**
     * @tc.name: IpcPermissionReq::SetPublishId
     * @tc.desc: Set PublishId of the Ipc Notify Publish Result Request
     * @tc.type: FUNC
     */
    void SetPermissionLevel(int32_t permissionLevel)
    {
        permissionLevel_ = permissionLevel;
    }
private:
    int32_t permissionLevel_ = 0;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_IPC_PERMISSION_REQ_H
