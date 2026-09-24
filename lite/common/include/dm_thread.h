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


#ifndef DM_THREAD_H
#define DM_THREAD_H

#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    pthread_mutex_t mtx;
} DmMutex;

typedef struct {
    pthread_cond_t cond;
    DmMutex* mtx;
} DmCond;

typedef struct {
    pthread_t th;
    bool running;
} DmThread;

typedef struct {
    sem_t sem;
} DmSem;

int DmMutexInit(DmMutex* m);
void DmMutexLock(DmMutex* m);
void DmMutexUnlock(DmMutex* m);
void DmMutexDestroy(DmMutex* m);




uint64_t DmGetTimestampMs(void);

#ifdef __cplusplus
}
#endif

#endif
