/**
 * <pre>
 *
 *     author : wgc
 *     time   : 2021/12/15
 *     desc   :
 *     version: 1.0
 * 
 * </pre>
 */


#include <openssl/types.h>
#include <openssl/evp.h>
#include "header/sm/sm3_crypto.h"
#include "header/CommonUtils.h"
#include <header/empty.h>
#include <string.h>

std::string sm3Digest(unsigned char msg[]) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen;
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    size_t msgLen = strlen(reinterpret_cast<const char *const>(msg));
    EVP_DigestInit_ex(mdCtx, EVP_sm3() , null);
    EVP_DigestUpdate(mdCtx, msg, msgLen);
    EVP_DigestFinal_ex(mdCtx, digest, &digestLen);
    EVP_MD_CTX_free(mdCtx);
    std::string digestHex = arr2hex(digest, digestLen);
    return digestHex;
}