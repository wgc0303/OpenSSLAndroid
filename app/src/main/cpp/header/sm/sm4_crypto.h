/**
 * <pre>
 *
 *     author : wgc
 *     time   : 2021/04/28
 *     desc   :
 *     version: 1.0
 * 
 * </pre>
 */


#ifndef OPENSSL_ANDROID_SM4_CRYPTO_H
#define OPENSSL_ANDROID_SM4_CRYPTO_H

#include "jni.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
* sm4cbc加密
*/
jbyteArray sm4CbcEncrypt(JNIEnv *env, unsigned char key[], unsigned char iv[], unsigned char content[]);

/**
 * sm4cbc解密
 */
jbyteArray sm4CbcDecrypt(JNIEnv *env, unsigned char key[], unsigned char iv[], unsigned char cipherText[],size_t cipherLen);

#ifdef  __cplusplus
}
#endif

#endif //OPENSSL_ANDROID_SM4_TOOLS_H
