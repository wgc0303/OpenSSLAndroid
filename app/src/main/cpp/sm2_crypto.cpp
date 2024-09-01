/**
 * <pre>
 *
 *     author : wgc
 *     time   : 2021/12/14
 *     desc   :
 *     version: 1.0
 * 
 * </pre>
 */


#include "header/sm/sm2_crypto.h"
#include <openssl/evp.h>
#include "openssl/obj_mac.h"
#include <header/LogUtils.h>
#include <header/CommonUtils.h>
#include <openssl/ec.h>
#include <iostream>
#include <header/empty.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <memory>
#include <iostream>

//SM2签名ID
#define SIGN_ID "123"

//sm2私钥数据
const unsigned char private_key_data[] = {
        0x70, 0x69, 0x8b, 0xa3, 0x57, 0x6d, 0x30, 0x61,
        0xc1, 0x06, 0xe8, 0x25, 0x68, 0xd7, 0x5f, 0xd8,
        0x66, 0xe0, 0x1f, 0x3d, 0xad, 0x2c, 0x7f, 0x71,
        0xbb, 0xc9, 0x50, 0xbb, 0x6a, 0x03, 0x56, 0x4d
};
/**********************sm2公钥多种表现形式*********************/
//sm2 公钥数据形式一： 由x,y两组数据构成，前面加04表示未压缩
const unsigned char public_key_data[] = {
        POINT_CONVERSION_UNCOMPRESSED,
        //x
        0x86, 0xae, 0x5f, 0x84, 0xc2, 0x8c, 0x2f, 0x23,
        0x76, 0x7f, 0xef, 0x3d, 0x06, 0xc0, 0x00, 0xd3,
        0xa7, 0x8f, 0x45, 0x66, 0x19, 0xd6, 0xda, 0xb8,
        0x22, 0x31, 0xcd, 0xd9, 0x73, 0x38, 0x94, 0xae,
        //y
        0x93, 0xd4, 0xab, 0x93, 0x2c, 0x16, 0x05, 0x39,
        0xe0, 0x89, 0x21, 0x87, 0x97, 0xf9, 0xc7, 0x62,
        0x49, 0x81, 0x88, 0x00, 0x66, 0x5e, 0xea, 0x20,
        0x93, 0xad, 0x34, 0x96, 0x7c, 0xf8, 0xd5, 0x5f
};

//sm2 公钥数据形式二：压缩形式的公钥，由x计算出Y
const unsigned char public_key_compress_data[] = {
        0x03,
        //x
        0x86, 0xae, 0x5f, 0x84, 0xc2, 0x8c, 0x2f, 0x23,
        0x76, 0x7f, 0xef, 0x3d, 0x06, 0xc0, 0x00, 0xd3,
        0xa7, 0x8f, 0x45, 0x66, 0x19, 0xd6, 0xda, 0xb8,
        0x22, 0x31, 0xcd, 0xd9, 0x73, 0x38, 0x94, 0xae};

//sm2 公钥数据形式三：
//sm2 公钥数据 由x数据构成
const unsigned char public_key_x[] = {
        0x86, 0xae, 0x5f, 0x84, 0xc2, 0x8c, 0x2f, 0x23,
        0x76, 0x7f, 0xef, 0x3d, 0x06, 0xc0, 0x00, 0xd3,
        0xa7, 0x8f, 0x45, 0x66, 0x19, 0xd6, 0xda, 0xb8,
        0x22, 0x31, 0xcd, 0xd9, 0x73, 0x38, 0x94, 0xae};

//sm2 公钥数据 y数据
const unsigned char public_key_y[] = {
        0x93, 0xd4, 0xab, 0x93, 0x2c, 0x16, 0x05, 0x39,
        0xe0, 0x89, 0x21, 0x87, 0x97, 0xf9, 0xc7, 0x62,
        0x49, 0x81, 0x88, 0x00, 0x66, 0x5e, 0xea, 0x20,
        0x93, 0xad, 0x34, 0x96, 0x7c, 0xf8, 0xd5, 0x5f};
/**********************sm2公钥多种表现形式*********************/


/**********************pem格式公私钥*********************/

const char *public_pem = "-----BEGIN PUBLIC KEY-----\n"
                         "MFowFAYIKoEcz1UBgi0GCCqBHM9VAYItA0IABIauX4TCjC8jdn/vPQbAANOnj0Vm\n"
                         "GdbauCIxzdlzOJSuk9SrkywWBTngiSGHl/nHYkmBiABmXuogk600lnz41V8=\n"
                         "-----END PUBLIC KEY-----";

const char *private_pem = "-----BEGIN PRIVATE KEY-----\n"
                          "MIGIAgEAMBQGCCqBHM9VAYItBggqgRzPVQGCLQRtMGsCAQEEIHBpi6NXbTBhwQbo\n"
                          "JWjXX9hm4B89rSx/cbvJULtqA1ZNoUQDQgAEhq5fhMKMLyN2f+89BsAA06ePRWYZ\n"
                          "1tq4IjHN2XM4lK6T1KuTLBYFOeCJIYeX+cdiSYGIAGZe6iCTrTSWfPjVXw==\n"
                          "-----END PRIVATE KEY-----";

/**********************pem格式公私钥*********************/


/**
 *
 * @param content 原始字符数据
 * @return  加密后ASN.1编码后的hexString
 */
std::string sm2encrypt2hexString(unsigned char content[]) {

    EVP_PKEY_CTX *ctx;
    EVP_PKEY *evpKey = null;
    OSSL_PARAM_BLD *param_bld;
    OSSL_PARAM *params = null;
    param_bld = OSSL_PARAM_BLD_new();
    //上面的这种方式和下面的方式是一样的,二选一
    //方式一，可用未压缩和压缩后的公钥数据
    if (param_bld
        && OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                           OSSL_EC_curve_nid2name(NID_sm2), 0)
        && OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, public_key_data,
                                            sizeof(public_key_data))) {
        params = OSSL_PARAM_BLD_to_param(param_bld);
    }
        //方式二分别使用X，Y两组数据
        /*if ( param_bld
            && OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, OSSL_EC_curve_nid2name(NID_sm2), 0)
            && OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_EC_PUB_X, public_key_x, sizeof(public_key_x))
            && OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_EC_PUB_Y, public_key_y, sizeof(public_key_y))) {
            LOGD("添加参数成功");
            params = OSSL_PARAM_BLD_to_param(param_bld);
        }*/

    else {
        LOGD("参数添加失败");
        return string_empty;
    }

    //下面这两种方式都行
    ctx = EVP_PKEY_CTX_new_id(NID_sm2, null);
//    ctx = EVP_PKEY_CTX_new_from_name(null, "SM2", null);
    if (!ctx
        || !params
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &evpKey, EVP_PKEY_KEYPAIR, params) <= 0) {
        LOGD("导入失败");
        return string_empty;
    }

    ctx = EVP_PKEY_CTX_new(evpKey, null);
    if (!ctx || !evpKey) {
        LOGD("  创建失败");
        return string_empty;
    }

    //除了sm2 其他的一些算法会失败
    int re = EVP_PKEY_encrypt_init(ctx);
    if (re != 1) {
        LOGD("  初始化失败");
        return string_empty;
    }

    size_t dataSize = strlen(reinterpret_cast<const char *const>(content));

    size_t outLen = 0;
    /**
   长度域表达方式有两种：
    1、短格式byte<=127的长度域直接以16进制表示，例：32就为0x20; 2、长格式  127<byte<=255为 例：158就为819e   255<byte<=65535为 例：1500就为8205DC
   说明可以参考 https://blog.csdn.net/mao834099514/article/details/109078662
   sm2加密数据ASN.1编码格式由四部分组成 c1x+c1y+c3+c2, c1x+c1y称为c1
   c1x和c1y的ASN.1编码规格相同，数据为{0x02,长度域(0x20或0x21)，数据（32位或者33位）}，当c1x和c1y是大正数是前面需要加0 所以大负数是32位，大正数是33位
   c3为签名数据，其ASN.1的编码格式为{0x04,0x20(长度域固定32位)，32位数据}
   c2为加密数据，其长度跟明文长度一致， C2的ASN1编码的数据为{0x04,长度域，数据}
   sm2整体的ASN.1编码数据为(0x30,长度域（计算出c1ASN.1+c3ASN.1+c2ASN.1的总byte长度域表达式）,密文数据}
   */
    //计算加密后的为ASN.1编码的字节长度
    EVP_PKEY_encrypt(ctx, null, &outLen, content, dataSize);

    unsigned char out[outLen];
    memset(out, 0, sizeof(out));

    //加密，数据为ASN.1数据
    EVP_PKEY_encrypt(ctx, out, &outLen, content, dataSize);

    std::string encHexString = arr2hex(out, outLen);

/*    //分段打印
    size_t encHexStrLen = encHexString.size();
    for (int i = 0; i < encHexStrLen; i += 1024) {
        std::string s = encHexString.substr(i, i + 1024);
        LOGD("%s", s.c_str());
    }*/

//    std::string text = sm2decryptBuf2HexString(out, out_len);
//    LOGD("解密完成后数据     %s", text.c_str());

    //释放资源
    EVP_PKEY_free(evpKey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    CRYPTO_cleanup_all_ex_data();
    return encHexString;
}


SM2Ciphertext *sm2Ciphertext2Struct(const unsigned char **pp, long length) {
    const unsigned char *p = *pp;
    LOGD("ASN.1：%s", arr2hex(p, length).c_str());
    SM2Ciphertext *ret = new SM2Ciphertext();

    ASN1_SEQUENCE_ANY *seq = d2i_ASN1_SEQUENCE_ANY(nullptr, &p, length);
//    ASN1_OBJECT* seq = d2i_ASN1_OBJECT_(nullptr, &p, length);
    if (!seq) {
        LOGD("解析ANS.1结构体失败");
        delete ret;
        return null;
    }
//     seq = d2i_ASN1_SEQUENCE_ANY(&seq, &p, length);

    // 解析 C1X（椭圆曲线点X）
    auto field = sk_ASN1_TYPE_value(seq, 0);
    if (field && field->type == V_ASN1_INTEGER) {
        BIGNUM *c1x = ASN1_INTEGER_to_BN(field->value.integer, NULL);
        ret->C1X = c1x;
        char *c1xHex = BN_bn2hex(ret->C1X);
        LOGD("c1xHex：%s", c1xHex);
//        BN_free(c1x);
    }
    // 解析 C1Y（椭圆曲线点y）
    field = sk_ASN1_TYPE_value(seq, 1);
    if (field && field->type == V_ASN1_INTEGER) {
        BIGNUM *c1y = ASN1_INTEGER_to_BN(field->value.integer, NULL);
        ret->C1Y = c1y;
        char *c1yHex = BN_bn2hex(ret->C1Y);
        LOGD("c1yHex：%s", c1yHex);
//        BN_free(c1x);
    }

    // 解析 C3（哈希值）
    field = sk_ASN1_TYPE_value(seq, 2);
    if (field && field->type == V_ASN1_OCTET_STRING) {
        ret->C3 = (unsigned char *) OPENSSL_malloc(ASN1_STRING_length(field->value.asn1_string));
        memcpy(ret->C3, ASN1_STRING_get0_data(field->value.octet_string),
               ASN1_STRING_length(field->value.asn1_string));
    }
    LOGD("C3：%s", arr2hex(ret->C3, ASN1_STRING_length(field->value.asn1_string)).c_str());

    // 解析 C2（加密数据）
    field = sk_ASN1_TYPE_value(seq, 3);
    if (field && field->type == V_ASN1_OCTET_STRING) {
        ret->C2 = (unsigned char *) OPENSSL_malloc(ASN1_STRING_length(field->value.asn1_string));
        memcpy(ret->C2, ASN1_STRING_get0_data(field->value.asn1_string),
               ASN1_STRING_length(field->value.asn1_string));
        ret->C2Len = ASN1_STRING_length(field->value.asn1_string);
    }
    LOGD("C2：%s", arr2hex(ret->C2, ASN1_STRING_length(field->value.asn1_string)).c_str());

    delete(seq);
    *pp = p;
    return ret;
}


// 定义 SM2 ASN.1 模板
ASN1_SEQUENCE(SM2CiphertextASN1) = {
        ASN1_SIMPLE(SM2CiphertextASN1, C1X, ASN1_INTEGER),
        ASN1_SIMPLE(SM2CiphertextASN1, C1Y, ASN1_INTEGER),
        ASN1_SIMPLE(SM2CiphertextASN1, C3, ASN1_OCTET_STRING),
        ASN1_SIMPLE(SM2CiphertextASN1, C2, ASN1_OCTET_STRING)
}ASN1_SEQUENCE_END(SM2CiphertextASN1)

IMPLEMENT_ASN1_FUNCTIONS(SM2CiphertextASN1)

int sm2Struct2Ciphertext(BIGNUM *C1X, BIGNUM *C1Y, unsigned char *C3, unsigned char *C2,
                         int C2Len, unsigned char **sm2Der) {

    SM2CiphertextASN1 *sm2CiphertextAsn1 = new SM2CiphertextASN1();
    // 编码C1X为 DER 格式
    sm2CiphertextAsn1->C1X = ASN1_INTEGER_new();
    BN_to_ASN1_INTEGER(C1X, sm2CiphertextAsn1->C1X);
//    BIGNUM *newC1X = ASN1_INTEGER_to_BN(sm2CiphertextAsn1->C1X, NULL);
//    char *newC1xHex = BN_bn2hex(newC1X);
//    LOGD("newC1xHex：%s", newC1xHex);

    // 编码C1Y为 DER 格式
    sm2CiphertextAsn1->C1Y = ASN1_INTEGER_new();
    BN_to_ASN1_INTEGER(C1Y, sm2CiphertextAsn1->C1Y);
//    BIGNUM *newC1Y = ASN1_INTEGER_to_BN( sm2CiphertextAsn1->C1Y, NULL);
//    char *newC1yHex = BN_bn2hex(newC1Y);
//    LOGD("newC1yHex：%s", newC1yHex);


    // 编码C3为 DER 格式
    sm2CiphertextAsn1->C3 = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(sm2CiphertextAsn1->C3, C3, 32);
//    int c3derLen = 0;
//    unsigned char* c3der = NULL;
//    c3derLen = i2d_ASN1_OCTET_STRING(sm2CiphertextAsn1->C3, &c3der);
//    LOGD("c3der：%s", arr2hex(c3der, c3derLen).c_str());


    // 编码C2为 DER 格式
    sm2CiphertextAsn1->C2 = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(sm2CiphertextAsn1->C2, C2, C2Len);
//    int c2derLen = 0;
//    unsigned char* c2der = NULL;
//    c2derLen = i2d_ASN1_OCTET_STRING( sm2CiphertextAsn1->C2, &c2der);
//    LOGD("c2der：%s", arr2hex(c2der, c2derLen).c_str());

    // 编码为 ASN.1 DER 格式
//    unsigned char *sm2Der = NULL;
    int derLen = i2d_SM2CiphertextASN1(sm2CiphertextAsn1, sm2Der);
    SM2CiphertextASN1_free(sm2CiphertextAsn1);
    return derLen;

}


/**
 *
 * @param enData 加密后ASN.1编码的二进制数据
 * @param enLen  加密后ASN.1编码的二进制数据长度
 * @return 解密后原始数据hex字符串
 */
std::string sm2decryptBuf2HexString(const unsigned char *enData, size_t enLen) {

    EVP_PKEY_CTX *ctx;
    EVP_PKEY *evpKey = null;
    BIGNUM *privateBN;
    OSSL_PARAM_BLD *param_bld;
    OSSL_PARAM *params;
    privateBN = BN_bin2bn(private_key_data, sizeof(private_key_data), null);
    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld
        && OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                           OSSL_EC_curve_nid2name(NID_sm2), 0)
        && OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, privateBN)) {
        params = OSSL_PARAM_BLD_to_param(param_bld);
    } else {
        LOGD("参数添加失败");
        return string_empty;
    }


    //下面这两种方式都行
//    ctx = EVP_PKEY_CTX_new_id(NID_sm2, null);
    ctx = EVP_PKEY_CTX_new_from_name(null, "SM2", null);
    if (!ctx
        || !params
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &evpKey, EVP_PKEY_KEYPAIR, params) <= 0) {
        LOGD("导入失败");
        return string_empty;
    }


    ctx = EVP_PKEY_CTX_new(evpKey, null);
    if (!ctx || !evpKey) {
        LOGD("  创建失败");
        return string_empty;
    }


    //解密初始化
    EVP_PKEY_decrypt_init(ctx);
    size_t out_len = 0;
    //计算出明文长度
    EVP_PKEY_decrypt(ctx, null, &out_len, enData, enLen);
    //给明文分配内存
    unsigned char out[out_len];
    memset(out, 0, sizeof(out));
    //解密
    EVP_PKEY_decrypt(ctx, out, &out_len, enData, enLen);
    std::string textHex = arr2hex(out, out_len);

    EVP_PKEY_free(evpKey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    BN_free(privateBN);
    CRYPTO_cleanup_all_ex_data();

    return textHex;
}

//读取PEM私钥字符串进行签名
std::string sm2Sign2ASN1HexString(unsigned char data[]) {

    EVP_PKEY_CTX *ctx;
    EVP_PKEY *evpKey = null;

    BIO *priBio = BIO_new_mem_buf(private_pem, -1);
    PEM_read_bio_PrivateKey(priBio, &evpKey, 0, null);
    BIO_free_all(priBio);

    ctx = EVP_PKEY_CTX_new(evpKey, null);

    if (!ctx || !evpKey) {
        LOGD("  创建失败");
        return string_empty;
    }

    size_t data_size = strlen(reinterpret_cast<const char *const>(data));
    size_t idLen = strlen(SIGN_ID);

    unsigned char sign[100];
    size_t signLen = sizeof(sign);

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_MD_CTX_set_pkey_ctx(mctx, ctx);


    if (EVP_PKEY_CTX_set1_id(ctx, SIGN_ID, idLen) <= 0
        || EVP_DigestSignInit(mctx, null, EVP_sm3(), null, evpKey) <= 0
        || EVP_DigestSignUpdate(mctx, data, data_size) <= 0
        || EVP_DigestSignFinal(mctx, sign, &signLen) <= 0) {
        return string_empty;
    }

    //释放资源
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(evpKey);
    EVP_PKEY_CTX_free(ctx);
    CRYPTO_cleanup_all_ex_data();

    std::string signHex = arr2hex(sign, signLen);

    return signHex;

}

/*std::string sm2Sign2ASN1HexString(unsigned char data[]) {

    EVP_PKEY_CTX *ctx;
    EVP_PKEY *evpKey = null;
    BIGNUM *privateBN;
    OSSL_PARAM_BLD *param_bld;
    OSSL_PARAM *params;
    privateBN = BN_bin2bn(private_key_data, sizeof(private_key_data), null);
    param_bld = OSSL_PARAM_BLD_new();
    //如果不是PEM格式的密钥，签名需要同时导入公私钥数据
    if (param_bld
        && OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                           OSSL_EC_curve_nid2name(NID_sm2), 0)
        && OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, public_key_data,
                                            sizeof(public_key_data))
        && OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, privateBN)) {
        params = OSSL_PARAM_BLD_to_param(param_bld);
    } else {
        LOGD("参数添加失败");
        return string_empty;
    }


    //下面这两种方式都行
    ctx = EVP_PKEY_CTX_new_id(NID_sm2, null);
//    ctx = EVP_PKEY_CTX_new_from_name(null, "SM2", null);
    if (!ctx
        || !params
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &evpKey, EVP_PKEY_KEYPAIR, params) <= 0) {
        LOGD("导入失败");
        return string_empty;
    }

    ctx = EVP_PKEY_CTX_new(evpKey, null);

    if (!ctx || !evpKey) {
        LOGD("  创建失败");
        return string_empty;
    }

    size_t data_size = strlen(reinterpret_cast<const char *const>(data));
    size_t idLen = strlen(SIGN_ID);

    unsigned char sign[100];
    size_t signLen = sizeof(sign);

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_MD_CTX_set_pkey_ctx(mctx, ctx);


    if (EVP_PKEY_CTX_set1_id(ctx, SIGN_ID, idLen) <= 0
        || EVP_DigestSignInit(mctx, null, EVP_sm3(), null, evpKey) <= 0
        || EVP_DigestSignUpdate(mctx, data, data_size) <= 0
        || EVP_DigestSignFinal(mctx, sign, &signLen) <= 0) {
        return string_empty;
    }

    //释放资源
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(evpKey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    BN_free(privateBN);
    CRYPTO_cleanup_all_ex_data();

    std::string signHex = arr2hex(sign, signLen);

    return signHex;

}*/

bool sm2VerifyASN1Data(unsigned char data[], unsigned char sign[], size_t signLen) {

    EVP_PKEY_CTX *ctx;
    EVP_PKEY *evpKey = null;

    //读取pem公钥字符数据到EVP_PKEY
    BIO *pubBio = BIO_new_mem_buf(public_pem, -1);
    PEM_read_bio_PUBKEY(pubBio, &evpKey, 0, null);
    BIO_free_all(pubBio);

    ctx = EVP_PKEY_CTX_new(evpKey, null);

    if (!ctx || !evpKey) {
        LOGD("  创建失败");
        return false;
    }

    size_t data_size = strlen(reinterpret_cast<const char *const>(data));
    size_t idLen = strlen(SIGN_ID);

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_MD_CTX_set_pkey_ctx(mctx, ctx);

    if (EVP_PKEY_CTX_set1_id(ctx, SIGN_ID, idLen) != 1
        || EVP_DigestVerifyInit(mctx, null, EVP_sm3(), null, evpKey) != 1
        || EVP_DigestVerifyUpdate(mctx, data, data_size) != 1) {
        return false;
    }
    int verify = EVP_DigestVerifyFinal(mctx, sign, signLen);

    //释放资源
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(evpKey);
    EVP_PKEY_CTX_free(ctx);
    CRYPTO_cleanup_all_ex_data();

    return verify == 1;

}


void generateKeyPair() {

    EVP_PKEY *evpKey = EVP_EC_gen("SM2");
    unsigned char pub[256];
    size_t pubLen = 0;
    EVP_PKEY_get_octet_string_param(evpKey, OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof(pub), &pubLen);
    std::string pubKey = arr2hex(pub, pubLen);
    LOGD("sm2 压缩公钥\n%s", pubKey.c_str());

    BIGNUM *bnPri = NULL;
    EVP_PKEY_get_bn_param(evpKey, OSSL_PKEY_PARAM_PRIV_KEY, &bnPri);
    char *priHex = BN_bn2hex(bnPri);
    LOGD("sm2 私钥\n%s", priHex);

    priKeyHexGenPubKeyHex(priHex);

    BIO *pubBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pubBio, evpKey);
    char *pubPem = bio2Char(pubBio);
    LOGD("sm2 pem公钥\n%s", pubPem);

    BIO *priBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(priBio, evpKey, null, null, 0, null, null);
    char *priPem = bio2Char(priBio);
    LOGD("sm2 pem私钥\n%s", priPem);

    privatePemKeyGenPublicKey(priPem);
    BIO_free_all(pubBio);
    BIO_free_all(priBio);
    BN_free(bnPri);
    EVP_PKEY_free(evpKey);
}


void privatePemKeyGenPublicKey(char *priKey) {

    BIO *keybio = NULL;
    keybio = BIO_new_mem_buf(priKey, -1);

    if (keybio == NULL) {
        LOGE("BIO_new_mem_buf failed");
        return;
    }
    EVP_PKEY *ecKey = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
    if (ecKey == NULL) {
        LOGE("PEM_read_bio_ECPrivateKey failed");
        BIO_free(keybio);
        return;
    }

    BIO *pub = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pub, ecKey);
    int pub_len = BIO_pending(pub);
    char *pub_key = new char[pub_len + 1];
    BIO_read(pub, pub_key, pub_len);
    pub_key[pub_len] = '\0';

    LOGE("公钥   %s", pub_key);
    unsigned char pub1[256];
    size_t pubLen = 0;
    EVP_PKEY_get_octet_string_param(ecKey, OSSL_PKEY_PARAM_PUB_KEY, pub1, sizeof(pub1), &pubLen);
    std::string pubKey = arr2hex(pub1, pubLen);
    LOGE("sm2 压缩公钥\n%s", pubKey.c_str());

    delete[] pub_key;
    BIO_free(pub);
    BIO_free(keybio);
    EVP_PKEY_free(ecKey);
}


void priKeyHexGenPubKeyHex(char *priHex) {
    BIGNUM *bnPri = NULL;
    BN_hex2bn(&bnPri, priHex);
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    EC_POINT *pubPoint = EC_POINT_new(group);
    EC_POINT_mul(group, pubPoint, bnPri, NULL, NULL, ctx);
    unsigned char pub[65];
    unsigned long pubLen = 65;

    EC_POINT_point2oct(group, pubPoint, POINT_CONVERSION_UNCOMPRESSED, pub, pubLen, ctx);
    char *pubHex = EC_POINT_point2hex(group, pubPoint, POINT_CONVERSION_UNCOMPRESSED, ctx);
    LOGD("sm2 私钥hex推导出公钥hex\n%s", pubHex);
    BN_CTX_free(ctx);
    BN_free(bnPri);
    EC_GROUP_free(group);
    EC_POINT_free(pubPoint);
}






