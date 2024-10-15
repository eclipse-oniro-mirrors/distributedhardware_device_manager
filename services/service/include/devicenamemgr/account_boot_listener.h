/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ACCOUNT_BOOT_LISTENER_H
#define OHOS_ACCOUNT_BOOT_LISTENER_H
#include <atomic>

#include "dm_data_share_common_event.h"
#include "local_device_name_mgr.h"
namespace OHOS {
namespace DistributedHardware {
typedef enum SaTriggerFlag {
    DM_SA_READY,
    DATA_SHARE_SA_REDDY
} SaTriggerFlag;
class AccountBootListener {
public:
    AccountBootListener();
    ~AccountBootListener();
    void RegisterAccountBootCb();
    void DoAccountBootProc();
    void SetSaTriggerFlag(SaTriggerFlag triggerFlag);
    void InitDataShareEvent();
    void DataShareCallback();
private:
    /**
     * @brief flag for is registered callback for account boot event
     * true: has register the callback
     * false: NOT register the callback
     */
    std::atomic<bool> isRegAccountBootCb_;
    std::shared_ptr<LocalDeviceNameMgr> localDeviceMgr_;
    std::atomic<bool> isDmSaReady_;
    std::atomic<bool> isDataShareReady_;
    static std::mutex lock_;
    std::shared_ptr<DmDataShareCommonEventManager> dataShareCommonEventManager_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_ACCOUNT_BOOT_LISTENER_H