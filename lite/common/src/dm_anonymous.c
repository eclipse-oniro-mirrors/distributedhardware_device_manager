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


#include "dm_anonymous.h"
#include "securec.h"
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>

const char* DM_PRINT_LIST_SPLIT = ", ";
const int32_t DM_LIST_SPLIT_LEN = 2;
const int DM_ANONY_MIN_LEN_FOR_MASK = 2;


int DmMmapDmStringIntInit(DmMmapDmStringInt* m)
{
    m->data = NULL;
    m->size = 0;
    m->cap = 0;
    return 0;
}

int DmMmapDmStringIntInsert(DmMmapDmStringInt* m, DmString key, int32_t val)
{
    if (m->size >= m->cap) {
        int nc = m->cap == 0 ? 8 : m->cap * 2;
        DmMmapEntryDmStringInt* nd = (DmMmapEntryDmStringInt*)malloc(nc * sizeof(DmMmapEntryDmStringInt));
        if (nd && m->data && m->size > 0) {
            if (memcpy_s(nd, nc * sizeof(DmMmapEntryDmStringInt), m->data,
                m->size * sizeof(DmMmapEntryDmStringInt)) != 0) {
                free(nd);
                return -1;
            }
            free(m->data);
        }
        if (!nd) {
            return -1;
        }
        m->data = nd;
        m->cap = nc;
    }
    m->data[m->size].key = key;
    m->data[m->size].val = val;
    m->size++;
    return 0;
}

int DmMmapDmStringIntSize(DmMmapDmStringInt* m)
{
    return m->size;
}

void DmMmapDmStringIntClear(DmMmapDmStringInt* m)
{
    for (int i = 0; i < m->size; i++) {
        DmStringDestroy(&m->data[i].key);
    }
    m->size = 0;
}

void DmMmapDmStringIntDestroy(DmMmapDmStringInt* m)
{
    DmMmapDmStringIntClear(m);
    free(m->data);
    m->data = NULL;
    m->size = 0;
    m->cap = 0;
}

DmString DmGetAnonyString(const DmString* value)
{
    const int32_t shortIdLength = 20;
    const int32_t plaintextLength = 4;
    const int32_t minIdLength = 3;
    int strLen = DmStringSize(value);
    if (strLen < minIdLength) {
        return DmStringCreate("******");
    }
    DmString res = DmStringCreateEmpty();
    const char* v = DmStringCstr(value);
    if (strLen <= shortIdLength) {
        DmStringAppendChar(&res, v[0]);
        DmStringAppend(&res, "******");
        DmStringAppendChar(&res, v[strLen - 1]);
    } else {
        DmString prefix = DmStringSubstr(value, 0, plaintextLength);
        DmStringAppend(&res, DmStringCstr(&prefix));
        DmStringDestroy(&prefix);
        DmStringAppend(&res, "******");
        DmString suffix = DmStringSubstr(value, strLen - plaintextLength, plaintextLength);
        DmStringAppend(&res, DmStringCstr(&suffix));
        DmStringDestroy(&suffix);
    }
    return res;
}

DmString DmGetAnonyInt32(int32_t value)
{
    char buf[32];
    if (snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "%d", value) < 0) {
        return DmStringCreate("******");
    }
    int len = (int)strlen(buf);
    if (len == 1) {
        buf[0] = '*';
        return DmStringCreate(buf);
    }
    for (int i = 1; i < len - 1; i++) {
        buf[i] = '*';
    }
    return DmStringCreate(buf);
}

DmString DmGetAnonyUint64(uint64_t value)
{
    char buf[32];
    if (snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "%" PRIu64, value) < 0) {
        return DmStringCreate("******");
    }
    int len = (int)strlen(buf);
    if (len == 1) {
        buf[0] = '*';
        return DmStringCreate(buf);
    }
    if (len == DM_ANONY_MIN_LEN_FOR_MASK) {
        buf[1] = '*';
        return DmStringCreate(buf);
    }
    for (int i = 1; i < len - 1; i++) {
        buf[i] = '*';
    }
    return DmStringCreate(buf);
}

DmString DmGetAnonyInt(int value)
{
    char buf[32];
    if (snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "%d", value) < 0) {
        return DmStringCreate("******");
    }
    int len = (int)strlen(buf);
    if (len == 1) {
        buf[0] = '*';
        return DmStringCreate(buf);
    }
    for (int i = 1; i < len - 1; i++) {
        buf[i] = '*';
    }
    return DmStringCreate(buf);
}

bool DmIsNumberString(const DmString* inputString)
{
    if (DmStringSize(inputString) == 0 || DmStringSize(inputString) > DM_ANONY_MAX_INT_LEN) {
        LOGE("inputString is Null or inputString length is too long");
        return false;
    }
    const int32_t minAsciiNum = 48;
    const int32_t maxAsciiNum = 57;
    const char* s = DmStringCstr(inputString);
    for (int i = 0; i < DmStringSize(inputString); i++) {
        int num = (int)s[i];
        if (num >= minAsciiNum && num <= maxAsciiNum) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

DmString DmConvertCharArrayToString(const char* srcData, uint32_t srcLen)
{
    if (srcData == NULL || srcLen == 0 || srcLen >= DM_ANONY_MAX_MESSAGE_LEN) {
        LOGE("Invalid parameter.");
        return DmStringCreateEmpty();
    }
    char* dstData = (char*)calloc(srcLen + 1, 1);
    if (memcpy_s(dstData, srcLen + 1, srcData, srcLen) != 0) {
        LOGE("memcpy_s failed.");
        free(dstData);
        return DmStringCreateEmpty();
    }
    DmString temp = DmStringCreate(dstData);
    free(dstData);
    return temp;
}

int64_t DmStringToInt64(const DmString* str, int32_t base)
{
    if (DmStringEmpty(str)) {
        LOGE("Str is empty.");
        return 0;
    }
    char* nextPtr = NULL;
    int64_t result = strtoll(DmStringCstr(str), &nextPtr, base);
    if (errno == ERANGE || nextPtr == NULL || nextPtr == DmStringCstr(str) || *nextPtr != '\0') {
        LOGE("parse int error");
        return 0;
    }
    return result;
}

void DmVersionSplitToInt(const DmString* str, char split, DmVec_int* numVec)
{
    if (DmStringEmpty(str)) {
        return;
    }
    const char* s = DmStringCstr(str);
    int len = DmStringSize(str);
    if (len < 0 || len >= DM_ANONY_MAX_MESSAGE_LEN) {
        return;
    }
    char* copy = (char*)malloc(len + 1);
    if (!copy) {
        return;
    }
    if (memcpy_s(copy, len + 1, s, len + 1) != 0) {
        free(copy);
        return;
    }
    int pos = 0;
    for (int i = 0; i <= len; i++) {
        if (i == len || copy[i] == split) {
            copy[i] = '\0';
            DmVec_int_Push(numVec, atoi(copy + pos));
            pos = i + 1;
        }
    }
    free(copy);
}

bool DmCompareVecNum(DmVec_int* srcVecNum, DmVec_int* sinkVecNum)
{
    int minSize = DmVec_int_Size(srcVecNum) < DmVec_int_Size(sinkVecNum) ?
        DmVec_int_Size(srcVecNum) : DmVec_int_Size(sinkVecNum);
    for (int index = 0; index < minSize; index++) {
        int32_t* sv = DmVec_int_At(srcVecNum, index);
        int32_t* sk = DmVec_int_At(sinkVecNum, index);
        if (*sv > *sk) {
            return true;
        } else if (*sv < *sk) {
            return false;
        }
    }
    if (DmVec_int_Size(srcVecNum) > DmVec_int_Size(sinkVecNum)) {
        return true;
    }
    return false;
}

bool DmIsString(const DmJsonItemObject* jsonObj, const DmString* key)
{
    DmJsonItemObject item = DmJsonItemObjectAt(jsonObj, DmStringCstr(key));
    return DmJsonItemObjectIsString(&item);
}

bool DmIsUint16(const DmJsonItemObject* jsonObj, const DmString* key)
{
    DmJsonItemObject item = DmJsonItemObjectAt(jsonObj, DmStringCstr(key));
    return DmJsonItemObjectIsNumberInteger(&item);
}
