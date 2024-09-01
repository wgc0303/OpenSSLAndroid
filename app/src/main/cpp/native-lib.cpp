#include <jni.h>
#include <string.h>
#include <header/LogUtils.h>
#include <header/CommonUtils.h>
#include <header/sm/sm2_crypto.h>
#include "header/sm/sm4_crypto.h"
#include <header/sm/sm3_crypto.h>
#include <header/rsa_crypto.h>
#include <header/empty.h>
#include <openssl/cmac.h>

extern "C" JNIEXPORT void JNICALL
Java_cn_wgc_openssl_MainActivity_jniGenerateSm2KeyPair(JNIEnv *env, jobject /* this */) {
    generateKeyPair();
}

extern "C" JNIEXPORT jstring JNICALL
Java_cn_wgc_openssl_MainActivity_jniSm2Encrypt2ASN1HexString(
        JNIEnv *env,
        jobject /* this */,
        jbyteArray content) {
    char *data = convertJByteArrayToChars(env, content);
    std::string enc = sm2encrypt2hexString(reinterpret_cast<unsigned char *>(data));
    free(data);
    return env->NewStringUTF(enc.c_str());
}


extern "C" JNIEXPORT jstring JNICALL
Java_cn_wgc_openssl_MainActivity_jniSm2Encrypt2Struct(
        JNIEnv *env,
        jobject /* this */,
        jbyteArray content) {
    char *data = convertJByteArrayToChars(env, content);
    std::string enc = sm2encrypt2hexString(reinterpret_cast<unsigned char *>(data));
    free(data);

    /*****转c1c2c3****/
    char *derChar = (char *) malloc(strlen(enc.c_str()));
    unsigned int derLen = 0;
    hexStrToByte(const_cast<char *>(enc.c_str()), reinterpret_cast<unsigned char *>(derChar),
                 &derLen);
    const unsigned char *der = reinterpret_cast<const unsigned char *>(derChar);
    SM2Ciphertext *strutCip = sm2Ciphertext2Struct(&der, derLen);

//    //strut转der
//    unsigned char *sm2Der = NULL;
//    int sm2derLen = sm2Struct2Ciphertext(strutCip->C1X, strutCip->C1Y, strutCip->C3, strutCip->C2,
//                                         strutCip->C2Len, sm2Der);

//java的数据格式直接是04+c1+c2+c3
    std::string headHex = "04";
    char *c1xHex = BN_bn2hex(strutCip->C1X);
    char *c1yHex = BN_bn2hex(strutCip->C1Y);
    std::string c2hex = arr2hex(reinterpret_cast<const unsigned char *>(strutCip->C2),
                                strutCip->C2Len).c_str();
    std::string c3hex = arr2hex(reinterpret_cast<const unsigned char *>(strutCip->C3), 32).c_str();
    std::string c1c2c3Hex = headHex.append(c1xHex).append(c1yHex).append(c2hex).append(
            c3hex).c_str();
    LOGD("c1c2c3:  %s", c1c2c3Hex.c_str());
//    jbyteArray dstArray = hexString2jByteArray(env, c1c2c3Hex.c_str());
/*****转c1c2c3****/

    OPENSSL_free(c1xHex);
    OPENSSL_free(c1yHex);
    BN_free(strutCip->C1X);
    BN_free(strutCip->C1Y);
    free(strutCip);
    return env->NewStringUTF(c1c2c3Hex.c_str());
}


extern "C" JNIEXPORT jstring JNICALL
Java_cn_wgc_openssl_MainActivity_jniStruct2ASN1(
        JNIEnv *env,
        jobject /* this */,
        jbyteArray c1c2c3) {

    //java的数据格式直接是04+c1+c2+c3
    char *c1c2c3Char = convertJByteArrayToChars(env, c1c2c3);
    size_t totalSize = env->GetArrayLength(c1c2c3);
    size_t c1xLen = 32;
    size_t c1yLen = 32;
    size_t c3Len = 32;
    size_t c2Len = totalSize - c1xLen - c1yLen - c3Len - 1;

    char *c1x = (char *) malloc(c1xLen);
    char *c1y = (char *) malloc(c1yLen);
    char *c3 = (char *) malloc(c3Len);
    char *c2 = (char *) malloc(totalSize - c1xLen - c1yLen - c3Len - 1);

    int startIndex = 1;
    memcpy(c1x, c1c2c3Char + startIndex, c1xLen);

    startIndex += c1xLen;
    memcpy(c1y, c1c2c3Char + startIndex, c1yLen);

    startIndex += c1yLen;
    memcpy(c2, c1c2c3Char + startIndex, totalSize - c1xLen - c1yLen - c3Len - 1);

    startIndex += c2Len;
    memcpy(c3, c1c2c3Char + startIndex, c3Len);
    BIGNUM *c1xBn = NULL;
    BN_hex2bn(&c1xBn, arr2hex(reinterpret_cast<const unsigned char *>(c1x), c1xLen).c_str());

    BIGNUM *c1yBn = NULL;
    BN_hex2bn(&c1yBn, arr2hex(reinterpret_cast<const unsigned char *>(c1y), c1yLen).c_str());

    //strut转der
    unsigned char *sm2Der = NULL;
    int sm2derLen = sm2Struct2Ciphertext(c1xBn, c1yBn, reinterpret_cast<unsigned char *>(c3),
                                         reinterpret_cast<unsigned char *>(c2),
                                         c2Len, &sm2Der);
    // 清理
    BN_free(c1xBn);
    BN_free(c1yBn);
    //注：c,c++以数组作为参数，实际传递的是指针，而不是值，因此长度需提前计算并当参数传入
    std::string content = arr2hex(sm2Der, sm2derLen);
    free(c1x);
    free(c1y);
    free(c2);
    free(c3);
    free(c1c2c3Char);
    return env->NewStringUTF(content.c_str());

}

extern "C" JNIEXPORT jstring JNICALL
Java_cn_wgc_openssl_MainActivity_jniSm2Sign2HexString(
        JNIEnv *env,
        jobject /* this */,
        jbyteArray asn_data) {

    char *data = convertJByteArrayToChars(env, asn_data);

    std::string signHex = sm2Sign2ASN1HexString(reinterpret_cast<unsigned char *>(data));
    free(data);
    return env->NewStringUTF(signHex.c_str());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_cn_wgc_openssl_MainActivity_jniSm2VerifyASN1SignData(
        JNIEnv *env,
        jobject /* this */,
        jbyteArray content,
        jbyteArray asn_sign_data) {

    char *contentData = convertJByteArrayToChars(env, content);
    char *signData = convertJByteArrayToChars(env, asn_sign_data);
    size_t signLen = env->GetArrayLength(asn_sign_data);
    bool verify = sm2VerifyASN1Data(reinterpret_cast<unsigned char *>(contentData),
                                    reinterpret_cast< unsigned char *>(signData), signLen);
    free(contentData);
    free(signData);
    return verify;
}


extern "C" JNIEXPORT jstring JNICALL
Java_cn_wgc_openssl_MainActivity_jniSm2DecryptASN12HexString(
        JNIEnv *env,
        jobject /* this */, jbyteArray asn_data) {

    char *buf = convertJByteArrayToChars(env, asn_data);
    size_t le = env->GetArrayLength(asn_data);
    std::string text = sm2decryptBuf2HexString(reinterpret_cast<const unsigned char *>(buf), le);
    free(buf);
    return env->NewStringUTF(text.c_str());
}


extern "C" JNIEXPORT jstring JNICALL
Java_cn_wgc_openssl_MainActivity_jniSM3Digest(
        JNIEnv *env,
        jobject /* this */,
        jbyteArray content) {

    char *data = convertJByteArrayToChars(env, content);
    std::string digest = sm3Digest(reinterpret_cast<unsigned char *>(data));
    free(data);
    return env->NewStringUTF(digest.c_str());
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_cn_wgc_openssl_MainActivity_jniSM4CBCEncrypt(
        JNIEnv *env,
        jobject /* this */,
        jbyteArray content) {
    const char *kv = "1234567812345678";
    char *contentData = convertJByteArrayToChars(env, content);
    jbyteArray cipherArray = sm4CbcEncrypt(env, (unsigned char *) kv,
                                           (unsigned char *) kv,
                                           reinterpret_cast<unsigned char *>(contentData));
    free(contentData);
    return cipherArray;
}
extern "C" JNIEXPORT jbyteArray JNICALL
Java_cn_wgc_openssl_MainActivity_jniSM4CBCDecrypt(
        JNIEnv *env,
        jobject /* this */,
        jbyteArray cipherArray) {

    const char *kv = "1234567812345678";

    char *cipher = convertJByteArrayToChars(env, cipherArray);
    size_t cipherLen = env->GetArrayLength(cipherArray);
    jbyteArray contentArray = sm4CbcDecrypt(env, (unsigned char *) kv, (unsigned char *) kv,
                                            reinterpret_cast<unsigned char *>(cipher), cipherLen);

    free(cipher);

    return contentArray;
}

extern "C" JNIEXPORT jstring JNICALL
Java_cn_wgc_openssl_MainActivity_jniRsaEncrypt(
        JNIEnv *env,
        jobject /* this */,
        jbyteArray content) {

    char *data = convertJByteArrayToChars(env, content);
    std::string enc = rsaPublicKeyEncrypt(reinterpret_cast<unsigned char *>(data));
    free(data);
    return env->NewStringUTF(enc.c_str());
}


extern "C" JNIEXPORT jstring JNICALL
Java_cn_wgc_openssl_MainActivity_jniRsaDecrypt(
        JNIEnv *env,
        jobject /* this */, jbyteArray enData) {

    char *buf = convertJByteArrayToChars(env, enData);
    size_t le = env->GetArrayLength(enData);
    std::string text = rsaPrivateKeyDecrypt(reinterpret_cast<const unsigned char *>(buf), le);
    free(buf);
    return env->NewStringUTF(text.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_cn_wgc_openssl_MainActivity_jniRsaSign(
        JNIEnv *env,
        jobject /* this */,
        jbyteArray content) {

    char *data = convertJByteArrayToChars(env, content);
    std::string signHex = rsaPrivateKeySign(reinterpret_cast<unsigned char *>(data));
    free(data);
    return env->NewStringUTF(signHex.c_str());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_cn_wgc_openssl_MainActivity_jniRsaVerify(
        JNIEnv *env,
        jobject /* this */,
        jbyteArray content,
        jbyteArray sign) {

    char *data = convertJByteArrayToChars(env, content);
    char *signData = convertJByteArrayToChars(env, sign);
    size_t signLen = env->GetArrayLength(sign);
    bool verify = rsaPublicVerify(reinterpret_cast<unsigned char *>(data),
                                  reinterpret_cast<unsigned char *>(signData), signLen);
    free(data);
    free(signData);
    return verify;
}