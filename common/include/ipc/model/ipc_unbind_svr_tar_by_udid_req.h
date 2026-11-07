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

#ifndef OHOS_DM_IPC_UNBIND_SVR_TAR_BY_UDID_REQ_H
#define OHOS_DM_IPC_UNBIND_SVR_TAR_BY_UDID_REQ_H

#include "ipc_req.h"

namespace OHOS {
namespace DistributedHardware {
class IpcUnbindSvrTarByUdidReq : public IpcReq {
    DECLARE_IPC_MODEL(IpcUnbindSvrTarByUdidReq);

public:
    const std::string &GetPeerUdid() const
    {
        return peerUdid_;
    }

    void SetPeerUdid(const std::string &peerUdid)
    {
        peerUdid_ = peerUdid;
    }

    int64_t GetServiceId() const
    {
        return serviceId_;
    }

    void SetServiceId(int64_t serviceId)
    {
        serviceId_ = serviceId;
    }

    const std::string &GetUnbindParam() const
    {
        return unbindParam_;
    }

    void SetUnbindParam(const std::string &unbindParam)
    {
        unbindParam_ = unbindParam;
    }

private:
    std::string peerUdid_;
    int64_t serviceId_ = 0;
    std::string unbindParam_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_IPC_UNBIND_SVR_TAR_BY_UDID_REQ_H
