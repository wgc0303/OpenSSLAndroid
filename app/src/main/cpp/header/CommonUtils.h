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
#include <openssl/types.h>

#ifndef COMMON_UTILS_JNI_H
#define COMMON_UTILS_JNI_H


#ifdef  __cplusplus
extern "C" {
#endif

char *convertJByteArrayToChars(JNIEnv *env, jbyteArray byteArray);

std::string arr2hex(const unsigned char *arr, size_t len);

char *bio2Char(BIO *bio);

int hexStrToByte(char *str, unsigned char *out, unsigned int *outLen);
unsigned char *hex_to_bytes(const char *hex, size_t *out_len);

#ifdef  __cplusplus
}
#endif


#endif //COMMON_UTILS_JNI_H
