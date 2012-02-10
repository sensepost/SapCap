/*
SAPProx - SAP Proxy server component

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
/* Header for class com_sensepost_SAPProx_JniInterface */

#ifndef _Included_com_sensepost_SAPProx_jni_JniInterface
#define _Included_com_sensepost_SAPProx_JniInterface
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_sensepost_SAPProx_JniInterface
 * Method:    _doDecompress
 * Signature: ([I)[I
 */
JNIEXPORT jintArray JNICALL Java_com_sensepost_SAPProx_jni_JniInterface__1doDecompress
  (JNIEnv *, jobject, jintArray);

/*
 * Class:     com_sensepost_SAPProx_JniInterface
 * Method:    _doCompress
 * Signature: ([I)[I
 */
JNIEXPORT jintArray JNICALL Java_com_sensepost_SAPProx_jni_JniInterface__1doCompress
  (JNIEnv *, jobject, jintArray);

#ifdef __cplusplus
}
#endif
#endif
