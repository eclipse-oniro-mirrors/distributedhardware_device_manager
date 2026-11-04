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

#ifndef OHOS_DM_MINI_SDK_LOADER_H
#define OHOS_DM_MINI_SDK_LOADER_H

#include <dlfcn.h>
#include "dm_log.h"

namespace OHOS {
namespace DistributedHardware {
namespace MiniSdk {
class LibraryLease final {
public:
    explicit LibraryLease(const char *name) : handle_(dlopen(name, RTLD_NOW | RTLD_LOCAL))
    {
        if (handle_ == nullptr) {
            const char *error = dlerror();
            LOGW("mini sdk load failed: %{public}s, reason: %{public}s", name,
                error != nullptr ? error : "unknown error");
        }
    }
    ~LibraryLease()
    {
        if (handle_ != nullptr) {
            dlclose(handle_);
        }
    }
    LibraryLease(const LibraryLease &) = delete;
    LibraryLease &operator=(const LibraryLease &) = delete;
    void *Symbol(const char *name) const
    {
        return handle_ == nullptr ? nullptr : dlsym(handle_, name);
    }

private:
    void *handle_;
};

// Only for the fixed mini-sdk entry points that perform synchronous IPC.
// The lease outlives the call and every remote/parcel created by the adapter.
template <typename Result, typename... Args>
Result Call(const char *library, const char *symbol, Result fallback, Args... args)
{
    LibraryLease lease(library);
    auto function = reinterpret_cast<Result (*)(Args...)>(lease.Symbol(symbol));
    if (function == nullptr) {
        LOGW("mini sdk entry unavailable: %{public}s/%{public}s", library, symbol);
        return fallback;
    }
    return function(args...);
}
} // namespace MiniSdk
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_MINI_SDK_LOADER_H
