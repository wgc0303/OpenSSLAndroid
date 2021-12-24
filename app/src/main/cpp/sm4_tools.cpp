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

#include "openssl/evp.h"
#include "sm/sm4_tools.h"
#include "LogUtils.h"
#include <string.h>
#include <empty.h>

/**
 * sm4cbc加密
 */
jbyteArray sm4CbcEncrypt(JNIEnv *env, unsigned char key[], unsigned char iv[], unsigned char content[]) {
    size_t contentLen = strlen(reinterpret_cast<const char *const>(content));
    int outLen = 0, cipherTextLen;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    //设置padding
    //EVP_CIPHER_CTX_set_padding(ctx,EVP_PADDING_PKCS7);

    //指定加密算法，初始化加密key/iv
    EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), null, key, iv);

    //获取SM4块长度,长度为 16
    int blockSize = EVP_CIPHER_CTX_get_block_size(ctx);

    //计算加密后数据长度并分配内存空间
    unsigned char *out = (unsigned char *) malloc((contentLen / blockSize + 1) * blockSize);
    //清空内存空间
    memset(out, 0, (contentLen / blockSize + 1) * blockSize);

    EVP_EncryptUpdate(ctx, out, &outLen, (const unsigned char *) content, contentLen);
    cipherTextLen = outLen;

    EVP_EncryptFinal_ex(ctx, out + outLen, &outLen);
    cipherTextLen += outLen;

    EVP_CIPHER_CTX_free(ctx);
    CRYPTO_cleanup_all_ex_data();

    jbyteArray cipher = env->NewByteArray(cipherTextLen);
    //在堆中分配ByteArray数组对象成功，将拷贝数据到数组中
    env->SetByteArrayRegion(cipher, 0, cipherTextLen, (jbyte *) out);
    free(out);
    return cipher;
}

/**
 * sm4cbc解密
 */
jbyteArray sm4CbcDecrypt(JNIEnv *env, unsigned char key[], unsigned char iv[], unsigned char cipherText[],size_t cipherLen) {
    int outLen = 0, plaintextLen;

    unsigned char *out = (unsigned char *) malloc(cipherLen);
    memset(out, 0, cipherLen);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    //设置padding
    //EVP_CIPHER_CTX_set_padding(ctx,EVP_PADDING_PKCS7);

    EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), null, key, iv);
    EVP_DecryptUpdate(ctx, out, &outLen, (const unsigned char *) cipherText, cipherLen);
    plaintextLen = outLen;

    EVP_DecryptFinal_ex(ctx, out + outLen, &outLen);
    plaintextLen += outLen;

    EVP_CIPHER_CTX_free(ctx);
    CRYPTO_cleanup_all_ex_data();

    jbyteArray cipher = env->NewByteArray(plaintextLen);
    //在堆中分配ByteArray数组对象成功，将拷贝数据到数组中
    env->SetByteArrayRegion(cipher, 0, plaintextLen, (jbyte *) out);

    free(out);
    return cipher;
}
