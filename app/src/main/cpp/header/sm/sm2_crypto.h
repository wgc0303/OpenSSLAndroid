/**
 * <pre>
 *
 *     author : wgc
 *     time   : 2021/12/03
 *     desc   :
 *     version: 1.0
 * 
 * </pre>
 */


#ifndef OPENSSL_ANDROID_SM2_CRYPTO_H
#define OPENSSL_ANDROID_SM2_CRYPTO_H

#include "string"
#include "jni.h"
#include "openssl/asn1t.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <vector>

struct SM2Ciphertext {
    BIGNUM *C1X;          // 椭圆曲线点x
    BIGNUM *C1Y;          // 椭圆曲线点x
    unsigned char *C3;  // 哈希值
    unsigned char *C2;  // 加密数据
    int C2Len;
};

struct SM2CiphertextASN1 {
    ASN1_INTEGER *C1X;
    ASN1_INTEGER *C1Y;
    ASN1_OCTET_STRING *C3;
    ASN1_OCTET_STRING *C2;
};

std::string sm2encrypt2hexString(unsigned char content[]);

int sm2encrypt(unsigned char content[], unsigned char **der);

//sm2密文ASN.1转结构体
SM2Ciphertext *sm2Ciphertext2Struct(const unsigned char **pp, long length);

//sm2密文ASN.1转结构体
int sm2Struct2Ciphertext(BIGNUM *C1X, BIGNUM *C1Y, unsigned char *C3, unsigned char *C2,
                         int C2Len, unsigned char **sm2Der);

std::string sm2decryptBuf2HexString(const unsigned char *enData, size_t enLen);

std::string sm2Sign2ASN1HexString(unsigned char data[]);

bool sm2VerifyASN1Data(unsigned char data[], unsigned char sign[], size_t signLen);

void generateKeyPair();

void privatePemKeyGenPublicKey(char *priKey);

void priKeyHexGenPubKeyHex(char *priHex);


#endif //OPENSSL_ANDROID_SM2_CRYPTO_H
