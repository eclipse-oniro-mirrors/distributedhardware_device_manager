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

#ifndef OHOS_DM_IPC_NOTIFY_SVR_TRUSTED_PEER_STATE_REQ_H
#define OHOS_DM_IPC_NOTIFY_SVR_TRUSTED_PEER_STATE_REQ_H

#include "dm_device_info.h"
#include "ipc_req.h"

namespace OHOS {
namespace DistributedHardware {
class IpcNotifySvrTrustedPeerStateReq : public IpcReq {
    DECLARE_IPC_MODEL(IpcNotifySvrTrustedPeerStateReq);

public:
    const AuthInfo &GetAuthInfo() const
    {
        return authInfo_;
    }

    void SetAuthInfo(const AuthInfo &authInfo)
    {
        authInfo_ = authInfo;
    }

    const DmServiceTrustedPeer &GetDmServiceTrustedPeer() const
    {
        return peer_;
    }

    void SetDmServiceTrustedPeer(const DmServiceTrustedPeer &peer)
    {
        peer_ = peer;
    }

    int32_t GetPeerState() const
    {
        return peerState_;
    }

    void SetPeerState(int32_t peerState)
    {
        peerState_ = peerState;
    }

    int64_t GetServiceId() const
    {
        return serviceId_;
    }

    void SetServiceId(int64_t serviceId)
    {
        serviceId_ = serviceId;
    }

    DmRegisterServiceState GetDmRegisterServiceState()
    {
        return registerServiceState_;
    }

    void SetDmRegisterServiceState(const DmRegisterServiceState &registerServiceState)
    {
        registerServiceState_ = registerServiceState;
    }

private:
    AuthInfo authInfo_;
    DmServiceTrustedPeer peer_;
    int32_t peerState_ = 0;
    int64_t serviceId_ = -1;
    DmRegisterServiceState registerServiceState_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_IPC_NOTIFY_SVR_TRUSTED_PEER_STATE_REQ_H
