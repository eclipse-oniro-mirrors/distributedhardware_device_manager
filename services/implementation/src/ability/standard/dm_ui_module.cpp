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

#include "dm_ui_api.h"

#include "dm_dialog_manager.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
int32_t Invoke(uint32_t operation, const char *data, size_t size)
{
    if (operation > DM_UI_CLOSE || (data == nullptr && size != 0)) {
        return -1;
    }
    // Copy the borrowed bytes before the backend stores state or queues async work.
    const std::string params(data == nullptr ? "" : data, size);
    switch (operation) {
        case DM_UI_CONFIRM:
            DmDialogManager::GetInstance().ShowConfirmDialog(params);
            break;
        case DM_UI_SERVICE_CONFIRM:
            DmDialogManager::GetInstance().ShowServiceBindConfirmDialog(params);
            break;
        case DM_UI_PIN:
            DmDialogManager::GetInstance().ShowPinDialog(params);
            break;
        case DM_UI_INPUT:
            DmDialogManager::GetInstance().ShowInputDialog(params);
            break;
        case DM_UI_CLOSE:
            DmDialogManager::GetInstance().CloseDialog();
            break;
        default:
            return -1;
    }
    return 0;
}

const DmUiApi API = { DM_UI_API_VERSION, sizeof(DmUiApi), Invoke };

void *CreateSession(const DmUiSessionHost *host, void *connection)
{
    return host == nullptr ? nullptr : DmDialogManager::CreateSession(*host, connection);
}

int32_t InvokeSession(void *context, uint32_t operation, const char *data, size_t size)
{
    if (context == nullptr || operation > DM_UI_CLOSE || (data == nullptr && size != 0)) {
        return -1;
    }
    auto session = static_cast<DmDialogManager *>(context);
    const std::string params(data == nullptr ? "" : data, size);
    switch (operation) {
        case DM_UI_CONFIRM:
            session->ShowConfirmDialog(params);
            break;
        case DM_UI_SERVICE_CONFIRM:
            session->ShowServiceBindConfirmDialog(params);
            break;
        case DM_UI_PIN:
            session->ShowPinDialog(params);
            break;
        case DM_UI_INPUT:
            session->ShowInputDialog(params);
            break;
        case DM_UI_CLOSE:
            return session->CloseSession();
        default:
            return -1;
    }
    // Dispatch accepted. Visibility and closure are asynchronous events.
    return 0;
}

void Connected(void *context, void *remote, int32_t result)
{
    // The host retains a strong reference throughout this synchronous callback.
    sptr<IRemoteObject> object(static_cast<IRemoteObject *>(remote));
    static_cast<DmDialogManager *>(context)->OnAbilityConnectDone(AppExecFwk::ElementName(), object, result);
}

void Disconnected(void *context, int32_t result)
{
    static_cast<DmDialogManager *>(context)->OnAbilityDisconnectDone(AppExecFwk::ElementName(), result);
}

void DestroySession(void *context)
{
    DmDialogManager::DestroySession(static_cast<DmDialogManager *>(context));
}

const DmUiSessionApi SESSION_API = { DM_UI_SESSION_API_VERSION, sizeof(DmUiSessionApi), DM_UI_CAN_UNLOAD_DIALOG,
    CreateSession, InvokeSession, Connected, Disconnected, DestroySession };

} // namespace
} // namespace DistributedHardware
} // namespace OHOS

extern "C" const DmUiApi *DmGetUiApiV1()
{
    return &OHOS::DistributedHardware::API;
}

extern "C" const DmUiSessionApi *DmGetUiSessionApiV2()
{
    return &OHOS::DistributedHardware::SESSION_API;
}
