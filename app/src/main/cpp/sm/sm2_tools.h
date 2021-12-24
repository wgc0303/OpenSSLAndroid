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


#ifndef OPENSSL_ANDROID_SM2_TOOLS_H
#define OPENSSL_ANDROID_SM2_TOOLS_H

#include <string>
#include <jni.h>

std::string sm2encrypt2hexString(unsigned char content[]);

std::string sm2decryptBuf2HexString(const unsigned char *enData, size_t enLen);

std::string sm2Sign2ASN1HexString(unsigned char data[]);

bool sm2VerifyASN1Data(unsigned char data[], unsigned char sign[], size_t signLen);


#endif //OPENSSL_ANDROID_SM2_TOOLS_H
