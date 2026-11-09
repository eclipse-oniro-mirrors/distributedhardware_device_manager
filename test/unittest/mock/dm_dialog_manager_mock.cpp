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

#include "dm_dialog_manager_mock.h"
#include "dm_dialog_client.h"
#include "dm_ui_api.h"

namespace OHOS {
namespace DistributedHardware {

void DmDialogClient::ShowConfirmDialog(const std::string &param)
{
    ASSERT_NE(DmDialogManagerMock::dmDialogManagerMock, nullptr);
    DmDialogManagerMock::dmDialogManagerMock->ShowConfirmDialog(param);
}

void DmDialogClient::ShowPinDialog(const std::string &param)
{
    ASSERT_NE(DmDialogManagerMock::dmDialogManagerMock, nullptr);
    DmDialogManagerMock::dmDialogManagerMock->ShowPinDialog(param);
}

void DmDialogClient::ShowInputDialog(const std::string &param)
{
    ASSERT_NE(DmDialogManagerMock::dmDialogManagerMock, nullptr);
    DmDialogManagerMock::dmDialogManagerMock->ShowInputDialog(param);
}
void DmDialogClient::ShowServiceBindConfirmDialog(const std::string &param)
{
    if (DmDialogManagerMock::dmDialogManagerMock != nullptr) {
        DmDialogManagerMock::dmDialogManagerMock->ShowServiceBindConfirmDialog(param);
    }
}

void DmDialogClient::CloseDialog()
{
    if (DmDialogManagerMock::dmDialogManagerMock != nullptr) {
        DmDialogManagerMock::dmDialogManagerMock->CloseDialog();
    }
}

void DmDialogClient::ReleaseConfirmSession()
{
    if (DmDialogManagerMock::dmDialogManagerMock != nullptr) {
        DmDialogManagerMock::dmDialogManagerMock->ReleaseConfirmSession();
    }
}

void DmDialogClient::ReleaseSession(uint32_t operation)
{
    if (DmDialogManagerMock::dmDialogManagerMock != nullptr) {
        DmDialogManagerMock::dmDialogManagerMock->ReleaseSession(operation);
    }
}

int32_t InvokeDmUi(uint32_t operation, const char *data, size_t size)
{
    if (operation > DM_UI_CLOSE || (data == nullptr && size != 0)) {
        return -1;
    }
    // Fully isolate the loader entry for the supported dialog operations.
    return 0;
}
} // namespace DistributedHardware
} // namespace OHOS
