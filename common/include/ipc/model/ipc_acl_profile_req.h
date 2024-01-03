/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DM_IPC_ACL_PROFILE_REQ_H
#define OHOS_DM_IPC_ACL_PROFILE_REQ_H

#include "dm_device_info.h"
#include "ipc_req.h"

namespace OHOS {
namespace DistributedHardware {
class IpcAclProfileReq : public IpcReq {
    DECLARE_IPC_MODEL(IpcAclProfileReq);

public:
    /**
     * @tc.name: IpcAclProfileReq::GetFirstParam
     * @tc.desc: Ipc get first string parameter
     * @tc.type: FUNC
     */
    const std::string &GetUdid() const
    {
        return udid_;
    }

    /**
     * @tc.name: IpcAclProfileReq::SetFirstParam
     * @tc.desc: Ipc set first string parameter
     * @tc.type: FUNC
     */
    void SetUdid(const std::string &udid)
    {
        udid_ = udid;
    }

private:
    std::string udid_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_IPC_ACL_PROFILE_REQ_H
