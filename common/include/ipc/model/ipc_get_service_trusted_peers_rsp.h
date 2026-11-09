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

#ifndef OHOS_DM_IPC_GET_SERVICE_TRUSTED_PEERS_RSP_H
#define OHOS_DM_IPC_GET_SERVICE_TRUSTED_PEERS_RSP_H

#include "ipc_req.h"
#include "dm_device_info.h"

namespace OHOS {
namespace DistributedHardware {
class IpcGetServiceTrustedPeersRsp : public IpcRsp {
    DECLARE_IPC_MODEL(IpcGetServiceTrustedPeersRsp);
public:
    std::vector<DmServiceTrustedPeer> GetServiceTrustedPeers() const
    {
        return peers_;
    }

    void SetServiceTrustedPeers(const std::vector<DmServiceTrustedPeer> &peers)
    {
        peers_ = peers;
    }

private:
    std::vector<DmServiceTrustedPeer> peers_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_IPC_GET_SERVICE_TRUSTED_PEERS_RSP_H
