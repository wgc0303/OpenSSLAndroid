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


#include "sm/sm2_tools.h"
#include <openssl/evp.h>
#include "openssl/obj_mac.h"
#include <LogUtils.h>
#include <CommonUtils.h>
#include <openssl/ec.h>
#include <iostream>
#include <empty.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

//SM2签名ID
#define SIGN_ID "123"

//sm2私钥数据
const unsigned char private_key_data[] = {
        0x70, 0x69, 0x8b, 0xa3, 0x57, 0x6d, 0x30, 0x61,
        0xc1, 0x06, 0xe8, 0x25, 0x68, 0xd7, 0x5f, 0xd8,
        0x66, 0xe0, 0x1f, 0x3d, 0xad, 0x2c, 0x7f, 0x71,
        0xbb, 0xc9, 0x50, 0xbb, 0x6a, 0x03, 0x56, 0x4d
};

//sm2 公钥数据 由x,y两组数据构成，前面加04表示未压缩
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
    if (param_bld
        && OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                           OSSL_EC_curve_nid2name(NID_sm2), 0)
        && OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, public_key_data,
                                            sizeof(public_key_data))) {
        params = OSSL_PARAM_BLD_to_param(param_bld);
    }
        /*if ( param_bld
            && OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, OSSL_EC_curve_nid2name(NID_sm2), 0)
            && OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_EC_PUB_X, public_key_x, sizeof(public_key_x))
            && OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_EC_PUB_Y, public_key_y, sizeof(public_key_y))) {
            LOGD("添加参数成功");
            params = OSSL_PARAM_BLD_to_param(param_bld);
        }*/

    else {
        LOGD("参数添加失败");
        return null;
    }

    //下面这两种方式都行
    ctx = EVP_PKEY_CTX_new_id(NID_sm2, null);
//    ctx = EVP_PKEY_CTX_new_from_name(null, "SM2", null);
    if (!ctx
        || !params
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &evpKey, EVP_PKEY_KEYPAIR, params) <= 0) {
        LOGD("导入失败");
        return null;
    }

    ctx = EVP_PKEY_CTX_new(evpKey, null);
    if (!ctx || !evpKey) {
        LOGD("  创建失败");
        return null;
    }

    //除了sm2 其他的一些算法会失败
    int re = EVP_PKEY_encrypt_init(ctx);
    if (re != 1) {
        LOGD("  初始化失败");
        return null;
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
        return null;
    }


    //下面这两种方式都行
//    ctx = EVP_PKEY_CTX_new_id(NID_sm2, null);
    ctx = EVP_PKEY_CTX_new_from_name(null, "SM2", null);
    if (!ctx
        || !params
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &evpKey, EVP_PKEY_KEYPAIR, params) <= 0) {
        LOGD("导入失败");
        return null;
    }


    ctx = EVP_PKEY_CTX_new(evpKey, null);
    if (!ctx || !evpKey) {
        LOGD("  创建失败");
        return null;
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

std::string sm2Sign2ASN1HexString(unsigned char data[]) {

    EVP_PKEY_CTX *ctx;
    EVP_PKEY *evpKey = null;
    BIGNUM *privateBN;
    OSSL_PARAM_BLD *param_bld;
    OSSL_PARAM *params;
    privateBN = BN_bin2bn(private_key_data, sizeof(private_key_data), null);
    param_bld = OSSL_PARAM_BLD_new();
    //签名需要同时导入公私钥数据
    if (param_bld
        && OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                           OSSL_EC_curve_nid2name(NID_sm2), 0)
        && OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, public_key_data,
                                            sizeof(public_key_data))
        && OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, privateBN)) {
        params = OSSL_PARAM_BLD_to_param(param_bld);
    } else {
        LOGD("参数添加失败");
        return null;
    }


    //下面这两种方式都行
    ctx = EVP_PKEY_CTX_new_id(NID_sm2, null);
//    ctx = EVP_PKEY_CTX_new_from_name(null, "SM2", null);
    if (!ctx
        || !params
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &evpKey, EVP_PKEY_KEYPAIR, params) <= 0) {
        LOGD("导入失败");
        return null;
    }


    ctx = EVP_PKEY_CTX_new(evpKey, null);

    if (!ctx || !evpKey) {
        LOGD("  创建失败");
        return null;
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
        return null;
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

}

bool sm2VerifyASN1Data(unsigned char data[], unsigned char sign[], size_t signLen) {

    EVP_PKEY_CTX *ctx;
    EVP_PKEY *evpKey = null;
    OSSL_PARAM_BLD *param_bld;
    OSSL_PARAM *params;
    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld
        && OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                           OSSL_EC_curve_nid2name(NID_sm2), 0)
        && OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, public_key_data,
                                            sizeof(public_key_data))) {
        params = OSSL_PARAM_BLD_to_param(param_bld);
    } else {
        LOGD("参数添加失败");
        return false;
    }


    //下面这两种方式都行
    ctx = EVP_PKEY_CTX_new_id(NID_sm2, null);
//    ctx = EVP_PKEY_CTX_new_from_name(null, "SM2", null);
    if (!ctx
        || !params
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &evpKey, EVP_PKEY_KEYPAIR, params) <= 0) {
        LOGD("导入失败");
        return false;
    }


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
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    CRYPTO_cleanup_all_ex_data();

    return verify == 1;

}




