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

#include "dm_transport_msg.h"

#include "dm_anonymous.h"
#include "dm_log.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    const int32_t MAX_USER_ID_NUM = 5;
    const int32_t MAX_BACKGROUND_USER_ID_NUM = 5;
}
void ToJson(cJSON *jsonObject, const UserIdsMsg &userIdsMsg)
{
    if (jsonObject == nullptr) {
        LOGE("Json pointer is nullptr!");
        return;
    }
    cJSON *foregroundUserIdArr = cJSON_CreateArray();
    if (foregroundUserIdArr == nullptr) {
        return;
    }
    for (auto const &userId : userIdsMsg.foregroundUserIds) {
        cJSON_AddItemToArray(foregroundUserIdArr, cJSON_CreateNumber(userId));
    }
    cJSON_AddItemToObject(jsonObject, FOREGROUND_USERIDS_MSG_USERIDS_KEY, foregroundUserIdArr);

    cJSON *backgroundUserIdArr = cJSON_CreateArray();
    if (backgroundUserIdArr == nullptr) {
        return;
    }
    for (auto const &userId : userIdsMsg.backgroundUserIds) {
        cJSON_AddItemToArray(backgroundUserIdArr, cJSON_CreateNumber(userId));
    }
    cJSON_AddItemToObject(jsonObject, BACKGROUND_USERIDS_MSG_USERIDS_KEY, backgroundUserIdArr);
}

void FromJson(const cJSON *jsonObject, UserIdsMsg &userIdsMsg)
{
    if (jsonObject == nullptr) {
        LOGE("Json pointer is nullptr!");
        return;
    }
    cJSON *foregroundUserIdsArr = cJSON_GetObjectItem(jsonObject, FOREGROUND_USERIDS_MSG_USERIDS_KEY);
    if (cJSON_IsArray(foregroundUserIdsArr)) {
        int32_t arrSize = cJSON_GetArraySize(foregroundUserIdsArr);
        if (arrSize > MAX_USER_ID_NUM) {
            LOGE("Receive too many foreground userids, %{public}d", arrSize);
            return;
        }
        for (int32_t i = 0; i < arrSize; i++) {
            cJSON *userIdItem = cJSON_GetArrayItem(foregroundUserIdsArr, i);
            if (cJSON_IsNumber(userIdItem)) {
                uint32_t userId = static_cast<uint32_t>(userIdItem->valueint);
                userIdsMsg.foregroundUserIds.push_back(userId);
            }
        }
    }

    cJSON *backgroundUserIdsArr = cJSON_GetObjectItem(jsonObject, BACKGROUND_USERIDS_MSG_USERIDS_KEY);
    if (cJSON_IsArray(backgroundUserIdsArr)) {
        int32_t arrSize = cJSON_GetArraySize(backgroundUserIdsArr);
        if (arrSize > MAX_BACKGROUND_USER_ID_NUM) {
            LOGE("Receive too many background userids, %{public}d", arrSize);
            return;
        }
        for (int32_t i = 0; i < arrSize; i++) {
            cJSON *userIdItem = cJSON_GetArrayItem(backgroundUserIdsArr, i);
            if (cJSON_IsNumber(userIdItem)) {
                uint32_t userId = static_cast<uint32_t>(userIdItem->valueint);
                userIdsMsg.backgroundUserIds.push_back(userId);
            }
        }
    }
}

void ToJson(cJSON *jsonObject, const CommMsg &commMsg)
{
    if (jsonObject == nullptr) {
        LOGE("Json pointer is nullptr!");
        return;
    }
    cJSON_AddNumberToObject(jsonObject, COMM_MSG_CODE_KEY, commMsg.code);
    const char *msg = commMsg.msg.c_str();
    cJSON_AddStringToObject(jsonObject, COMM_MSG_MSG_KEY, msg);
}

void FromJson(const cJSON *jsonObject, CommMsg &commMsg)
{
    if (jsonObject == nullptr) {
        LOGE("Json pointer is nullptr!");
        return;
    }
    cJSON *codeObj = cJSON_GetObjectItem(jsonObject, COMM_MSG_CODE_KEY);
    if (cJSON_IsNumber(codeObj)) {
        commMsg.code = codeObj->valueint;
    }

    cJSON *msgObj = cJSON_GetObjectItem(jsonObject, COMM_MSG_MSG_KEY);
    if (cJSON_IsString(msgObj)) {
        commMsg.msg = msgObj->valuestring;
    }
}

std::string GetCommMsgString(const CommMsg &commMsg)
{
    cJSON *rootMsg = cJSON_CreateObject();
    if (rootMsg == nullptr) {
        LOGE("Create cJSON object failed.");
        return "";
    }
    ToJson(rootMsg, commMsg);
    char *msg = cJSON_PrintUnformatted(rootMsg);
    if (msg == nullptr) {
        cJSON_Delete(rootMsg);
        return "";
    }
    std::string msgStr = std::string(msg);
    cJSON_free(msg);
    cJSON_Delete(rootMsg);

    return msgStr;
}

void ToJson(cJSON *jsonObject, const NotifyUserIds &notifyUserIds)
{
    if (jsonObject == nullptr) {
        LOGE("Json pointer is nullptr!");
        return;
    }

    cJSON_AddStringToObject(jsonObject, DSOFTBUS_NOTIFY_USERIDS_UDIDKEY, notifyUserIds.remoteUdid.c_str());

    cJSON *userIdArr = cJSON_CreateArray();
    if (userIdArr == nullptr) {
        return;
    }
    for (auto const &userId : notifyUserIds.userIds) {
        cJSON_AddItemToArray(userIdArr, cJSON_CreateNumber(userId));
    }
    cJSON_AddItemToObject(jsonObject, DSOFTBUS_NOTIFY_USERIDS_USERIDKEY, userIdArr);
}

void FromJson(const cJSON *jsonObject, NotifyUserIds &notifyUserIds)
{
    if (jsonObject == nullptr) {
        LOGE("Json pointer is nullptr!");
        return;
    }

    cJSON *msgObj = cJSON_GetObjectItem(jsonObject, DSOFTBUS_NOTIFY_USERIDS_UDIDKEY);
    if (cJSON_IsString(msgObj)) {
        notifyUserIds.remoteUdid = msgObj->valuestring;
    }

    cJSON *userIdsArr = cJSON_GetObjectItem(jsonObject, DSOFTBUS_NOTIFY_USERIDS_USERIDKEY);
    if (cJSON_IsArray(userIdsArr)) {
        int32_t arrSize = cJSON_GetArraySize(userIdsArr);
        if (arrSize > MAX_USER_ID_NUM) {
            LOGE("Receive too many userids, %{public}d", arrSize);
            return;
        }
        for (int32_t i = 0; i < arrSize; i++) {
            cJSON *userIdItem = cJSON_GetArrayItem(userIdsArr, i);
            if (cJSON_IsNumber(userIdItem)) {
                uint32_t userId = static_cast<uint32_t>(userIdItem->valueint);
                notifyUserIds.userIds.push_back(userId);
            }
        }
    }
}

std::string NotifyUserIds::ToString()
{
    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        LOGE("failed to create cjson object");
        return "";
    }

    ToJson(msg, *this);
    char *retStr = cJSON_PrintUnformatted(msg);
    if (retStr == nullptr) {
        LOGE("to json is nullptr.");
        cJSON_Delete(msg);
        return "";
    }
    std::string ret = std::string(retStr);
    cJSON_Delete(msg);
    cJSON_free(retStr);
    return ret;
}
} // DistributedHardware
} // OHOS