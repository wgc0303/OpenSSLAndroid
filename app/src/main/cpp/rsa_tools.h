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


#ifndef OPENSSL_ANDROID_RSA_TOOLS_H
#define OPENSSL_ANDROID_RSA_TOOLS_H

#include <string>

std::string rsaPublicKeyEncrypt(unsigned char content[]);

std::string rsaPrivateKeyDecrypt(const unsigned char *enData, size_t enLen);

std::string rsaPrivateKeySign(unsigned char content[]);

bool rsaPublicVerify(unsigned char content[], unsigned char sign[], size_t signLen);

#endif //OPENSSL_ANDROID_RSA_TOOLS_H
