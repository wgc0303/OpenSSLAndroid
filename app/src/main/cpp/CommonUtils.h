/**
 * <pre>
 *
 *     author : wgc
 *     time   : 2021/12/16
 *     desc   :
 *     version: 1.0
 * 
 * </pre>
 */

#include <string>
#include <jni.h>

#ifndef COMMON_UTILS_JNI_H
#define COMMON_UTILS_JNI_H


#ifdef  __cplusplus
extern "C" {
#endif

char *convertJByteArrayToChars(JNIEnv *env, jbyteArray byteArray);

std::string arr2hex(const unsigned char *arr, size_t len);


#ifdef  __cplusplus
}
#endif


#endif //COMMON_UTILS_JNI_H
