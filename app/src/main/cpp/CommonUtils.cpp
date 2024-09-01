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


#include <header/LogUtils.h>
#include <jni.h>
#include <header/CommonUtils.h>
#include <string.h>
#include <header/empty.h>
#include <openssl/types.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

/**
 * jbyteArray转char
 */
char *convertJByteArrayToChars(JNIEnv *env, jbyteArray byteArray) {
    char *chars = null;
    jbyte *bytes;
    bytes = env->GetByteArrayElements(byteArray, null);
    int len = env->GetArrayLength(byteArray);
    chars = new char[len + 1];
    memset(chars, 0, static_cast<size_t>(len + 1));
    memcpy(chars, bytes, static_cast<size_t>(len));
    env->ReleaseByteArrayElements(byteArray, bytes, 0);
    return chars;
}

/**
 * 将hexarr 转成16进制的字符串
 */
std::string arr2hex(const unsigned char *arr, size_t len) {
    size_t i;
    std::string res;
    char tmp[3];
    const char *tab = "0123456789ABCDEF";

    res.reserve(len * 2 + 1);
    for (i = 0; i < len; ++i) {
        tmp[0] = tab[arr[i] >> 4];
        tmp[1] = tab[arr[i] & 0xf];
        tmp[2] = '\0';
        res.append(tmp);
    }

    return res;
}

char *bio2Char(BIO *bio) {
    BUF_MEM *mem;
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &mem);
    BIO_set_close(bio, BIO_NOCLOSE);
    char *buff = (char *) malloc(mem->length + 1);
    memcpy(buff, mem->data, mem->length);
    buff[mem->length] = '\0';
    BUF_MEM_free(mem);
    return buff;
}


int hexStrToByte(char *str, unsigned char *out, unsigned int *outLen) {
    char *p = str;
    char high, low;
    int cnt = 0;
    size_t tmpLen = strlen(p);
    while (cnt < (tmpLen / 2)) {
        if (*p <= 'F') {
            high = *p > '9' ? *p - 48 - 7 : *p - 48;
        } else {
            high = ((*p > '9') && *p <= 'f') ? *p - 48 - 7 : *p - 48;
        }
        if (*p <= 'F') {
            low = *(++p) > '9' ? *(p) - 48 - 7 : *(p) - 48;
        } else {
            low = (*(++p) > '9' && *p <= 'f') ? *(p) - 48 - 7 : *(p) - 48;
        }
        out[cnt] = ((high & 0x0f) << 4 | (low & 0x0f));
        p++;
        cnt++;
    }
    if (tmpLen % 2 != 0) {
        LOGD("数据有问题");
        if (*p <= 'F') {
            out[cnt] = *p > '9' ? *p - 48 - 7 : *p - 48;
        } else {
            out[cnt] = ((*p > '9') && *p <= 'f') ? *p - 48 - 7 : *p - 48;
        }
    }

    if (outLen != null) *outLen = tmpLen / 2 + tmpLen % 2;
    return tmpLen / 2 + tmpLen % 2;
}
