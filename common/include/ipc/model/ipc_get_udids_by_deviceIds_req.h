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

#ifndef OHOS_DM_IPC_GET_UDIDS_BY_DEVICEIDS_REQ_H
#define OHOS_DM_IPC_GET_UDIDS_BY_DEVICEIDS_REQ_H

#include "ipc_req.h"

namespace OHOS {
namespace DistributedHardware {
class IpcGetUdidsByDeviceIdsReq : public IpcReq {
    DECLARE_IPC_MODEL(IpcGetUdidsByDeviceIdsReq);
public:
    /**
     * @tc.name: IpcGetUdidsByDeviceIdsReq::GetDeviceIdList
     * @tc.desc: Get DeviceIdList of the Ipc Get Udids By Devices Request
     * @tc.type: FUNC
     */
    std::vector<std::string> GetDeviceIdList() const
    {
        return deviceIdList_;
    }

    /**
     * @tc.name: IpcGetUdidsByDeviceIdsReq::SetDeviceIdList
     * @tc.desc: Set DeviceIdList of the Ipc Get Udids By Devices Request
     * @tc.type: FUNC
     */
    void SetDeviceIdList(const std::vector<std::string> &deviceIdList)
    {
        deviceIdList_ = deviceIdList;
    }
private:
    std::vector<std::string> deviceIdList_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_IPC_GET_UDIDS_BY_DEVICEIDS_REQ_H