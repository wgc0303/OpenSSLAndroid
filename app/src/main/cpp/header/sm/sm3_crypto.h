/**
 * <pre>
 *
 *     author : wgc
 *     time   : 2021/12/15
 *     desc   :
 *     version: 1.0
 * 
 * </pre>
 */


#ifndef OPENSSL_ANDROID_SM3_CRYPTO_H
#define OPENSSL_ANDROID_SM3_CRYPTO_H

#include "string"
#include "jni.h"

std::string sm3Digest(unsigned char msg[]);

#endif //OPENSSL_ANDROID_SM3_CRYPTO_H
