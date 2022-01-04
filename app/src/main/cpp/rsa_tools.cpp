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


#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include "rsa_tools.h"
#include "openssl/types.h"
#include "openssl/bn.h"
#include <empty.h>
#include <openssl/pem.h>
#include "openssl/param_build.h"
#include "LogUtils.h"
#include "openssl/core_names.h"
#include "CommonUtils.h"

/**
 * 以下列举了RSA密钥的两种表示形式，该用哪种导入到EVP_PKEY,请自行选择
 */

const char *rsa_public_key = "-----BEGIN PUBLIC KEY-----\n"
                             "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCq7pL6rR9L+l0WTuwEiiKn8cAv\n"
                             "ihWoIZCuU5yiH8GgXoJlsrmJyi736l0fQnv69MLsKwImalp/F0u+o9hw9HiY+72q\n"
                             "kpjGZpwZYDYU509V4dv4IpyITWecAx1ELZHscV+BZ5HEZ73v4DESvJjzZ5rY7pN6\n"
                             "cs4rbOPbnnaPpFFZzwIDAQAB\n"
                             "-----END PUBLIC KEY-----";

const char *rsa_private_key = "-----BEGIN PRIVATE KEY-----\n"
                              "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKrukvqtH0v6XRZO\n"
                              "7ASKIqfxwC+KFaghkK5TnKIfwaBegmWyuYnKLvfqXR9Ce/r0wuwrAiZqWn8XS76j\n"
                              "2HD0eJj7vaqSmMZmnBlgNhTnT1Xh2/ginIhNZ5wDHUQtkexxX4FnkcRnve/gMRK8\n"
                              "mPNnmtjuk3pyzits49uedo+kUVnPAgMBAAECgYBP9x+MpVwcW8qbqp1QvFzdK8RI\n"
                              "mTVrfBRm8Ze34tpfD4e6UwPouc0CT0J0YtKEg2gDO1WcqimfBkN5ssYJhd06lEBq\n"
                              "NYxhbJ0esj2g5PFrS399lvnDRE/OBoH0ZhPGZBcmH+Jotf5U6vJtWobHY5V3Ja1n\n"
                              "uv1xBtdtg2GNKpiY+QJBAOLaGS/NPV2R53/qOlsFmNofdTt6RCL0tdPSTL9TigoI\n"
                              "5eJDBPTJJx5oXpSqJL8NDLLtfmfJX4jThBxHlqVqsqcCQQDA5RVvDDAW4AJYoW3w\n"
                              "C10TROqvzAPlnvqfVI+q7az7F2oivPsWkMeYEd7NiGomLF/0wRBKyNhL2QeqVkdg\n"
                              "xUyZAkB5Fn23PFBzL7xoVPiNOXGbjIshEmRoXELqLCj3P3pBXPqIScnNd8m/u2ow\n"
                              "5Jj0udx7bbW5ZI3wFSdBiRzqcwelAkEAh8Y4Cgw4JUHUJPKr4ZT+FLwjvU4LSCtZ\n"
                              "GaF55sSZR7w5du4yhrWt6Dpb66wjm28Ms8jZYOpyZSEEpj9IyrLVsQJBALSmIa7f\n"
                              "FTsMManISpWMHlsVe1FeizoF6wJ6zf7Kx3xyVLjVmrEQe7u9KcsGMcOH2cWS6Pqu\n"
                              "D8us4Og80LJgOv4=\n"
                              "-----END PRIVATE KEY-----";

/**
 * rsa 私有幂
 */
const unsigned char rsa_d[] = {0x4f, 0xf7, 0x1f, 0x8c, 0xa5, 0x5c, 0x1c, 0x5b,
                               0xca, 0x9b, 0xaa, 0x9d, 0x50, 0xbc, 0x5c, 0xdd,
                               0x2b, 0xc4, 0x48, 0x99, 0x35, 0x6b, 0x7c, 0x14,
                               0x66, 0xf1, 0x97, 0xb7, 0xe2, 0xda, 0x5f, 0x0f,
                               0x87, 0xba, 0x53, 0x03, 0xe8, 0xb9, 0xcd, 0x02,
                               0x4f, 0x42, 0x74, 0x62, 0xd2, 0x84, 0x83, 0x68,
                               0x03, 0x3b, 0x55, 0x9c, 0xaa, 0x29, 0x9f, 0x06,
                               0x43, 0x79, 0xb2, 0xc6, 0x09, 0x85, 0xdd, 0x3a,
                               0x94, 0x40, 0x6a, 0x35, 0x8c, 0x61, 0x6c, 0x9d,
                               0x1e, 0xb2, 0x3d, 0xa0, 0xe4, 0xf1, 0x6b, 0x4b,
                               0x7f, 0x7d, 0x96, 0xf9, 0xc3, 0x44, 0x4f, 0xce,
                               0x06, 0x81, 0xf4, 0x66, 0x13, 0xc6, 0x64, 0x17,
                               0x26, 0x1f, 0xe2, 0x68, 0xb5, 0xfe, 0x54, 0xea,
                               0xf2, 0x6d, 0x5a, 0x86, 0xc7, 0x63, 0x95, 0x77,
                               0x25, 0xad, 0x67, 0xba, 0xfd, 0x71, 0x06, 0xd7,
                               0x6d, 0x83, 0x61, 0x8d, 0x2a, 0x98, 0x98, 0xf9};

/**
 * rsa 公开幂
 */
const unsigned char rsa_n[] = {0x00, 0xaa, 0xee, 0x92, 0xfa, 0xad, 0x1f, 0x4b,
                               0xfa, 0x5d, 0x16, 0x4e, 0xec, 0x04, 0x8a, 0x22,
                               0xa7, 0xf1, 0xc0, 0x2f, 0x8a, 0x15, 0xa8, 0x21,
                               0x90, 0xae, 0x53, 0x9c, 0xa2, 0x1f, 0xc1, 0xa0,
                               0x5e, 0x82, 0x65, 0xb2, 0xb9, 0x89, 0xca, 0x2e,
                               0xf7, 0xea, 0x5d, 0x1f, 0x42, 0x7b, 0xfa, 0xf4,
                               0xc2, 0xec, 0x2b, 0x02, 0x26, 0x6a, 0x5a, 0x7f,
                               0x17, 0x4b, 0xbe, 0xa3, 0xd8, 0x70, 0xf4, 0x78,
                               0x98, 0xfb, 0xbd, 0xaa, 0x92, 0x98, 0xc6, 0x66,
                               0x9c, 0x19, 0x60, 0x36, 0x14, 0xe7, 0x4f, 0x55,
                               0xe1, 0xdb, 0xf8, 0x22, 0x9c, 0x88, 0x4d, 0x67,
                               0x9c, 0x03, 0x1d, 0x44, 0x2d, 0x91, 0xec, 0x71,
                               0x5f, 0x81, 0x67, 0x91, 0xc4, 0x67, 0xbd, 0xef,
                               0xe0, 0x31, 0x12, 0xbc, 0x98, 0xf3, 0x67, 0x9a,
                               0xd8, 0xee, 0x93, 0x7a, 0x72, 0xce, 0x2b, 0x6c,
                               0xe3, 0xdb, 0x9e, 0x76, 0x8f, 0xa4, 0x51, 0x59,
                               0xcf};

/**
 * rsa 合数模
 */
const unsigned char rsa_e[] = {0x01, 0x00, 0x01};

std::string rsaPublicKeyEncrypt(unsigned char content[]) {
    //以下两种方式都可以将RSA密钥导入EVP_PKEY

    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = null;

    OSSL_PARAM_BLD *param_bld;
    OSSL_PARAM *params;
    BIGNUM *n;
    BIGNUM *e;
    n = BN_bin2bn(rsa_n, sizeof(rsa_n), null);
    e = BN_bin2bn(rsa_e, sizeof(rsa_e), null);

    param_bld = OSSL_PARAM_BLD_new();

    if (param_bld
        && OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_N, n)
        && OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, e)) {
        params = OSSL_PARAM_BLD_to_param(param_bld);
    } else {
        LOGD("参数添加失败");
        return null;
    }

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, null);
//    ctx = EVP_PKEY_CTX_new_from_name(null, "RSA", null);
    if (!ctx
        || !params
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        LOGD("导入失败");
        return null;
    }

    ctx = EVP_PKEY_CTX_new(pkey, null);
    if (!ctx || !pkey) {
        LOGD("  创建失败");
        return null;
    }

    // 加密初始化
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        LOGD("  加密初始化失败");
        return null;
    }
    //设置填充模式，可省略 ，RSA加解密默认 RSA_PKCS1_PADDING
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    /**
     * 获取单个加密数据块的长度
     *  RSA_size()标记为过时 最新的方式 https://www.openssl.org/docs/man3.0/man3/RSA_size.html
     */
    int rsaSize = EVP_PKEY_get_size(pkey);

    size_t contentLen = strlen(reinterpret_cast<const char *const>(content));

    //单个数据块中原始数据的最大长度
    int blockSize = rsaSize - RSA_PKCS1_PADDING_SIZE;
    //计算加密后数据长度并分配内存空间
    size_t cipherLen = rsaSize * (contentLen / blockSize + 1);

    LOGD("RSA公钥加密运算");

    unsigned char *out = (unsigned char *) malloc(cipherLen);
    memset(out, 0, cipherLen);

    size_t outLen = 0; //输出数据大小 也用做输出空间偏移
    for (int i = 0; i < contentLen; i += blockSize) {
        //输出大小
        size_t outSize = rsaSize;
        //输入数据大小
        size_t inputSize = blockSize;
        if (contentLen - i < blockSize) {
            //最后一块数据
            inputSize = contentLen - i;
        }

        //加密参考 https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_encrypt.html
        if (EVP_PKEY_encrypt(ctx, null, &outSize, content + i, inputSize) <= 0
            || EVP_PKEY_encrypt(ctx,
                                out + outLen,        //输出空间
                                &outSize,   //输出空间大小，空间预留大小（输入）和实际加密后数据大小（输出）
                                content + i,         //输入数据
                                inputSize) <= 0)   //输入数据大小，块大小
        {
            LOGD("加密过程出错");
            return null;
        }
        outLen += outSize;
    }
    std::string cipher = arr2hex(out, outLen);
    //释放资源
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    BN_free(n);
    BN_free(e);
    CRYPTO_cleanup_all_ex_data();

    return cipher;
}

std::string rsaPrivateKeyDecrypt(const unsigned char *enData, size_t enLen) {
    //以下两种方式都可以将RSA密钥导入EVP_PKEY
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = null;

    BIO *bo = BIO_new_mem_buf(rsa_private_key, -1);
    PEM_read_bio_PrivateKey(bo, &pkey, 0, null);
    BIO_free_all(bo);

    ctx = EVP_PKEY_CTX_new(pkey, null);
    if (!ctx || !pkey) {
        LOGD("  创建失败");
        return null;
    }

    // 解密初始化
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        LOGD("  解密初始化失败");
        return null;
    }
    //设置填充模式，可省略 ，RSA加解密默认 RSA_PKCS1_PADDING
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);

    /**
     * 获取单个加密数据块的长度
     *  RSA_size()标记为过时 最新的方式 https://www.openssl.org/docs/man3.0/man3/RSA_size.html
     */
    int rsaSize = EVP_PKEY_get_size(pkey);

    //单个数据块中原始数据的最大长度
    int blockSize = rsaSize - RSA_PKCS1_PADDING_SIZE;
    //计算解密后明文数据长度并分配内存空间，这里是最大长度
    size_t textLen = blockSize * (enLen / rsaSize);
    LOGD("RSA私钥解密运算");

    unsigned char *out = (unsigned char *) malloc(textLen);
    memset(out, 0, textLen);

    //输出数据大小 也用做输出空间偏移
    size_t outLen = 0;
    for (int i = 0; i < enLen; i += rsaSize) {
        //输出大小
        size_t outSize = blockSize;
        //输入数据大小
        size_t inputSize = rsaSize;
        //解密参考 https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_decrypt.html
        if (EVP_PKEY_decrypt(ctx, NULL, &outSize, enData + i, inputSize) <= 0
            || EVP_PKEY_decrypt(ctx,
                                out + outLen,        //输出空间
                                &outSize,   //输出空间大小，空间预留大小（输入）和实际加密后数据大小（输出）
                                enData + i,         //输入数据
                                inputSize) <= 0)   //输入数据大小，块大小
        {
            LOGD("解密过程出错");
            return null;
        }
        outLen += outSize;
    }
    std::string textHex = arr2hex(out, outLen);
    //释放资源
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    CRYPTO_cleanup_all_ex_data();

    return textHex;
}


std::string rsaPrivateKeySign(unsigned char content[]) {

    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = null;
    OSSL_PARAM_BLD *param_bld;
    OSSL_PARAM *params;
    BIGNUM *d;
    BIGNUM *n;
    BIGNUM *e;
    d = BN_bin2bn(rsa_d, sizeof(rsa_d), null);
    n = BN_bin2bn(rsa_n, sizeof(rsa_n), null);
    e = BN_bin2bn(rsa_e, sizeof(rsa_e), null);

    param_bld = OSSL_PARAM_BLD_new();

    if (param_bld
        && OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_D, d)
        && OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_N, n)
        && OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, e)) {
        params = OSSL_PARAM_BLD_to_param(param_bld);
    } else {
        LOGD("参数添加失败");
        return null;
    }

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, null);
//    ctx = EVP_PKEY_CTX_new_from_name(null, "RSA", null);
    if (!ctx
        || !params
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        LOGD("导入失败");
        return null;
    }


    ctx = EVP_PKEY_CTX_new(pkey, null);
    if (!ctx || !pkey) {
        LOGD("  创建失败");
        return null;
    }

    size_t contentLen = strlen(reinterpret_cast<const char *const>(content));
    //生成hash算法上下文
    auto mctx = EVP_MD_CTX_new();
    EVP_SignInit(mctx, EVP_sha1());

    //消息生成hash值
    EVP_SignUpdate(mctx, content, contentLen);
    unsigned int signLen = 0;

//    memset(sign, 0, sizeof(sign));
    //计算出签名数据的长度
    EVP_SignFinal(mctx, null, &signLen, pkey);
    //分配内存
    unsigned char sign[signLen];
    EVP_SignFinal(mctx, sign, &signLen, pkey);

    std::string signHex = arr2hex(sign, signLen);

    //释放资源
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    BN_free(n);
    BN_free(d);
    BN_free(e);
    CRYPTO_cleanup_all_ex_data();


    return signHex;
}

bool rsaPublicVerify(unsigned char content[], unsigned char sign[], size_t signLen) {

    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = null;

    BIO *bo = BIO_new_mem_buf(rsa_public_key, -1);
    PEM_read_bio_PUBKEY(bo, &pkey, 0, null);
    BIO_free_all(bo);

    ctx = EVP_PKEY_CTX_new(pkey, null);
    if (!ctx || !pkey) {
        LOGD("  创建失败");
        return null;
    }

    size_t contentLen = strlen(reinterpret_cast<const char *const>(content));

    auto mctx = EVP_MD_CTX_new();
    EVP_VerifyInit(mctx, EVP_sha1());
    //生成单向散列
    EVP_VerifyUpdate(mctx, content, contentLen);
    //验签
    int verify = EVP_VerifyFinal(mctx, sign, signLen, pkey);
    //释放资源
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    CRYPTO_cleanup_all_ex_data();

    return verify == 1;

}