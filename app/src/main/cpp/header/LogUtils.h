/**
 * <pre>
 *
 *     author : wgc
 *     time   : 2021/11/26
 *     desc   :
 *     version: 1.0
 * 
 * </pre>
 */


#ifndef OPENSSL_ANDROID_LOG_UTILS_H
#define OPENSSL_ANDROID_LOG_UTILS_H

#include <android/log.h>

#define DEBUG 1 //日志开关，1为开，其它为关
#if(DEBUG == 1)
#define LOG_TAG "OPENSSL_JNI"
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE,LOG_TAG,__VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGV(...) NULL
#define LOGD(...) NULL
#define LOGI(...) NULL
#define LOGE(...) NULL
#endif

#endif //OPENSSL_ANDROID_LOG_UTILS_H
