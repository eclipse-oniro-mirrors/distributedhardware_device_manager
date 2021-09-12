/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "dm_timer.h"

#include <thread>

namespace OHOS {
namespace DistributedHardware {
DmTimer::DmTimer() {
    mStatus = DmTimerStatus::DM_STATUS_INIT;
}

DmTimerStatus DmTimer::Start(uint32_t timeOut, TimeoutHandle handle, void *data)
{
    DMLOG(DM_LOG_ERROR, "DmTimer start timeout(%d)\n", timeOut);
    if (mStatus != DmTimerStatus::DM_STATUS_INIT) {
        return DmTimerStatus::DM_STATUS_BUSY;
    }

    mTimeOutS = timeOut;
    mHandle = handle;
    mHandleData = data;

    if (CreateTimeFd()) {
        return DmTimerStatus::DM_STATUS_CREATE_ERROR;
    }

    mStatus = DmTimerStatus::DM_STATUS_RUNNING;
    mThread = std::thread(&DmTimer::WiteforTimeout, this);
    mThread.detach();

    return mStatus;
}

void DmTimer::Stop(int32_t code)
{
    DMLOG(DM_LOG_ERROR, "DmTimer Stop code (%d)\n", code);
    char event;
    event = 'S';
    if (mTimeFd[1]) {
        if (write(mTimeFd[1], &event, 1) < 0) {
            DMLOG(DM_LOG_ERROR, "DmTimer Stop timer failed %d \n", errno);
        }
    }

    return;
}

void DmTimer::WiteforTimeout()
{
    DMLOG(DM_LOG_ERROR, "DmTimer start timer at (%d)s" ,mTimeOutS);

    int32_t nfds = epoll_wait(mEpFd, mEvents, MAXEVENTS, mTimeOutS * 1000);
    if (nfds < 0) {
        DMLOG(DM_LOG_ERROR, "epoll_wait returned n=%d, error: %d", nfds, errno);
    }

    char event = 0;
    if (nfds > 0) {
        if (mEvents[0].events & EPOLLIN) {
            int num= read(mTimeFd[0], &event, 1);
            if (num > 0) {
                DMLOG(DM_LOG_INFO, "DmTimer exit with event %d", event);
            } else {
                DMLOG(DM_LOG_ERROR, "DmTimer exit with errno %d", errno);
            }
        }
        return;
    }

    mHandle(mHandleData);
    Release();

    DMLOG(DM_LOG_ERROR, "DmTimer end timer at (%d)s" ,mTimeOutS);
    return;
}

int32_t DmTimer::CreateTimeFd()
{
    DMLOG(DM_LOG_ERROR, "DmTimer creatTimeFd" );
    int ret = 0;

    ret = pipe(mTimeFd);
    if ( ret < 0) {
        DMLOG(DM_LOG_ERROR, "DmTimer CreateTimeFd fail:(%d) errno(%d)" ,ret, errno);
        return ret;
    }

    mEv.data.fd = mTimeFd[0];
    mEv.events = EPOLLIN | EPOLLET;
    mEpFd = epoll_create(MAXEVENTS);
    ret = epoll_ctl(mEpFd, EPOLL_CTL_ADD, mTimeFd[0], &mEv);
    if (ret != 0) {
        Release();
    }

    return ret;
}

void DmTimer::Release()
{
    mStatus = DmTimerStatus::DM_STATUS_INIT;
    close(mTimeFd[0]);
    close(mTimeFd[1]);
    close(mEpFd);
    mTimeFd[0] = 0;
    mTimeFd[1] = 0;
    mEpFd = 0;
}
}
}
