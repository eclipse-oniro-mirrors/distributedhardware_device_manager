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

#ifndef OHOS_DM_KV_ADAPTER_H
#define OHOS_DM_KV_ADAPTER_H

#include <atomic>
#include <condition_variable>
#include <map>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include "distributed_kv_data_manager.h"
#include "kvstore_death_recipient.h"
#include "kvstore_observer.h"

namespace OHOS {
namespace DistributedHardware {
typedef struct DmKVValue {
    std::string udidHash;
    std::string appID;
    std::string udid;
    int64_t lastModifyTime;
    explicit DmKVValue() : udidHash(""), appID(""), udid(""), lastModifyTime(0) {}
} DmKVValue;
void ConvertDmKVValueToJson(const DmKVValue &kvValue, std::string &result);
void ConvertJsonToDmKVValue(const std::string &result, DmKVValue &kvValue);
class KVAdapter : public DistributedKv::KvStoreDeathRecipient, public std::enable_shared_from_this<KVAdapter> {
public:
    KVAdapter() = default;
    virtual ~KVAdapter() = default;
    int32_t Init();
    void UnInit();
    int32_t ReInit();
    int32_t Put(const std::string &key, const std::string &value);
    int32_t Get(const std::string &key, std::string &value);

    void OnRemoteDied() override;

private:
    DistributedKv::Status GetLocalKvStorePtr();
    void RegisterKvStoreDeathListener();
    void UnregisterKvStoreDeathListener();

private:
    DistributedKv::AppId appId_;
    DistributedKv::StoreId storeId_;
    DistributedKv::DistributedKvDataManager kvDataMgr_;
    DistributedKv::DataType dataType_ = DistributedKv::DataType::TYPE_STATICS;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_ = nullptr;
    std::mutex kvAdapterMutex_;
    std::atomic<bool> isInited_ = false;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_KV_ADAPTER_H
