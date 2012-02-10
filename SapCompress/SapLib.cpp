/*
SapCompress - SAP JNI Decompression Component

Copyright (C) 2011 SensePost <ian@sensepost.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "SapLib.h"
#include "hpa101saptype.h"
#include "hpa104CsObject.h"
#include "hpa106cslzc.h"
#include "hpa107cslzh.h"
#include "hpa105CsObjInt.h"

JNIEXPORT jintArray JNICALL Java_com_sensepost_SAPProx_jni_JniInterface__1doDecompress
(JNIEnv * env, jobject jobj, jintArray in) {
    jsize len = env->GetArrayLength(in);
    SAP_BYTE *bufin = (SAP_BYTE*) malloc(len);
    jboolean copy = JNI_FALSE;
    jint *buf = env->GetIntArrayElements(in, &copy);
    for (int i = 0; i < len; i++) {
        bufin[i] = (SAP_BYTE) buf[i];
    }
    class CsObjectInt o;
    int rt;
    SAP_INT bytes_read;
    SAP_INT bytes_decompressed;
    SAP_BYTE *bufout = (SAP_BYTE*) malloc(len * 10);
    assert(sizeof (in) == sizeof (bufin));
    /*if (bufin[0x11] != 0x1F || bufin[0x12] != 0x9D) {
        //printf("ERROR: Stream is not compressed.\n");
    };*/
    SAP_INT slen = (SAP_INT) len;
    rt = o.CsDecompr(bufin + 12, slen, bufout, slen * 10, CS_INIT_DECOMPRESS, &bytes_read, &bytes_decompressed);
    switch (rt) {
        case CS_END_OF_STREAM:
            //printf("NOTICE: CS_END_OF_STREAM\n");
            break;
        case CS_END_INBUFFER:
            //printf("NOTICE: CS_END_INBUFFER\n");
            break;
        case CS_END_OUTBUFFER:
            //printf("NOTICE: CS_END_OUTBUFFER\n");
            break;
        case CS_E_OUT_BUFFER_LEN:
            //printf("NOTICE: CS_E_OUT_BUFFER_LEN\n");
            break;
        case CS_E_IN_BUFFER_LEN:
            //printf("NOTICE: CS_E_IN_BUFFER_LEN\n");
            break;
        case CS_E_MAXBITS_TOO_BIG:
            //printf("NOTICE: CS_E_MAXBITS_TOO_BIG\n");
            break;
        case CS_E_FILENOTCOMPRESSED:
            //printf("NOTICE: CS_E_FILENOTCOMPRESSED\n");
            break;
        case CS_E_IN_EQU_OUT:
            //printf("NOTICE: CS_E_IN_EQU_OUT\n");
            break;
        case CS_E_INVALID_ADDR:
            //printf("NOTICE: CS_EINVALID_ADDR\n");
            break;
        case CS_E_FATAL:
            //printf("NOTICE: CS_E_FATAL\n");
            break;
        default:
            //printf("NOTICE: CS_DEFAULT\n");
            break;
    };
    if (rt == CS_END_OF_STREAM || rt == CS_END_INBUFFER || rt == CS_END_OUTBUFFER) {
        //printf("NOTICE: %d bytes decompressed successfully to %d bytes.\n", bytes_read, bytes_decompressed);
    }
    else {
        //printf("ERROR: Unknown error.\n");
        bytes_decompressed = 0;
    }
    jintArray ret = env->NewIntArray(bytes_decompressed);
    jint *retBody;
    retBody = env->GetIntArrayElements(ret, false);
    for (int i = 0; i < bytes_decompressed; i++) {
        retBody[i] = (int) bufout[i];
    }
    env->ReleaseIntArrayElements(ret, retBody, 0);
    return (ret);
}

JNIEXPORT jintArray JNICALL Java_com_sensepost_SAPProx_jni_JniInterface__1doCompress
(JNIEnv * env, jobject jobj, jintArray in) {
    jsize len = env->GetArrayLength(in);
    SAP_BYTE *bufin = (SAP_BYTE*) malloc(len);
    jboolean copy = JNI_FALSE;
    jint *buf = env->GetIntArrayElements(in, &copy);
    for (int i = 0; i < len; i++) {
        bufin[i] = (SAP_BYTE) buf[i];
    }
    class CsObjectInt o;
    int rt;
    SAP_INT bytes_read;
    SAP_INT bytes_compressed;
    SAP_INT olen;
    SAP_BYTE *bufout = (SAP_BYTE*) malloc(len);
    assert(sizeof (in) == sizeof (bufin));
    SAP_INT slen = (SAP_INT) len;
    //rt = o.CsCompr(slen, bufin, slen, bufout, slen, CS_INIT_COMPRESS, &bytes_read, &bytes_compressed);
    //rt = o.CsCompr(slen, bufin, slen, bufout, slen, CS_INIT_COMPRESS, &bytes_read, &bytes_compressed);
    //rt = o.CsCompr(slen, bufin, slen, bufout, slen, CS_LZH, &bytes_read, &bytes_compressed);
    rt = o.CsCompr(slen, bufin, slen, bufout, slen, CS_INIT_COMPRESS, &bytes_read, &bytes_compressed);
    //rt = o.CsDecompr(bufin + 12, slen, bufout, slen * 10, CS_INIT_DECOMPRESS, &bytes_read, &bytes_decompressed);
    switch (rt) {
        case CS_END_OF_STREAM:
            //printf("NOTICE: CS_END_OF_STREAM\n");
            break;
        case CS_END_INBUFFER:
            //printf("NOTICE: CS_END_INBUFFER\n");
            break;
        case CS_END_OUTBUFFER:
            //printf("NOTICE: CS_END_OUTBUFFER\n");
            break;
        case CS_E_OUT_BUFFER_LEN:
            //printf("NOTICE: CS_E_OUT_BUFFER_LEN\n");
            break;
        case CS_E_IN_BUFFER_LEN:
            //printf("NOTICE: CS_E_IN_BUFFER_LEN\n");
            break;
        case CS_E_MAXBITS_TOO_BIG:
            //printf("NOTICE: CS_E_MAXBITS_TOO_BIG\n");
            break;
        case CS_E_FILENOTCOMPRESSED:
            //printf("NOTICE: CS_E_FILENOTCOMPRESSED\n");
            break;
        case CS_E_IN_EQU_OUT:
            //printf("NOTICE: CS_E_IN_EQU_OUT\n");
            break;
        case CS_E_INVALID_ADDR:
            //printf("NOTICE: CS_EINVALID_ADDR\n");
            break;
        case CS_E_FATAL:
            //printf("NOTICE: CS_E_FATAL\n");
            break;
        case CS_E_UNKNOWN_ALG:
            //printf("NOTICE: CS_E_UNKNOWN_ALG\n");
            break;
        default:
            //printf("NOTICE: CS_DEFAULT\n");
            break;
    };
    if (rt == CS_END_OF_STREAM || rt == CS_END_INBUFFER || rt == CS_END_OUTBUFFER) {
        //printf("NOTICE: %d bytes compressed successfully to %d bytes.\n", bytes_read, bytes_compressed);
    }
    else {
        //printf("ERROR: Unknown error.\n");
        bytes_compressed = 0;
    }
    jintArray ret = env->NewIntArray(bytes_compressed);
    jint *retBody;
    retBody = env->GetIntArrayElements(ret, false);
    for (int i = 0; i < bytes_compressed; i++) {
        retBody[i] = (int) bufout[i];
    }
    env->ReleaseIntArrayElements(ret, retBody, 0);
    return (ret);
}