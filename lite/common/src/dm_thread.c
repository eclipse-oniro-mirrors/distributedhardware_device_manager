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


#include "dm_thread.h"
#include <time.h>

#define DM_MS_PER_SEC 1000
#define DM_NS_PER_MS 1000000

int DmMutexInit(DmMutex* m)
{
    return pthread_mutex_init(&m->mtx, NULL);
}

void DmMutexLock(DmMutex* m)
{
    pthread_mutex_lock(&m->mtx);
}

void DmMutexUnlock(DmMutex* m)
{
    pthread_mutex_unlock(&m->mtx);
}

void DmMutexDestroy(DmMutex* m)
{
    pthread_mutex_destroy(&m->mtx);
}

uint64_t DmGetTimestampMs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * DM_MS_PER_SEC + (uint64_t)ts.tv_nsec / DM_NS_PER_MS;
}
