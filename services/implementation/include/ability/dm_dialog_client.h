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

#ifndef DM_DIALOG_CLIENT_H
#define DM_DIALOG_CLIENT_H

#include <cstdint>
#include <string>
#include "dm_single_instance.h"

namespace OHOS {
namespace DistributedHardware {
class DmDialogClient {
    DM_DECLARE_SINGLE_INSTANCE_BASE(DmDialogClient);
public:
    void ShowConfirmDialog(const std::string &param);
    void ShowServiceBindConfirmDialog(const std::string &param);
    void ShowPinDialog(const std::string &param);
    void ShowInputDialog(const std::string &param);
    void CloseDialog();
    void ReleaseConfirmSession();
    void ReleaseSession(uint32_t operation);
private:
    DmDialogClient() = default;
    ~DmDialogClient() = default;
};

int32_t InvokeDmUi(uint32_t operation, const char *data, size_t size);
} // namespace DistributedHardware
} // namespace OHOS

#endif
