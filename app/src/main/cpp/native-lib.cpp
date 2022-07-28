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
        jbyteArray asn_data) {
    char *data = convertJByteArrayToChars(env, asn_data);
    std::string enc = sm2encrypt2hexString(reinterpret_cast<unsigned char *>(data));
    free(data);
    return env->NewStringUTF(enc.c_str());
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
    jbyteArray contentArray = sm4CbcDecrypt(env, (unsigned char *) kv, (unsigned char *) kv, reinterpret_cast<unsigned char *>(cipher), cipherLen);

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