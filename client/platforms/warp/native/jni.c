#include <jni.h>
#include <stdlib.h>
#include "warp_transport.h"

typedef struct {
    JavaVM *vm;
    jobject protector;
    jmethodID protect;
    int32_t session;
} WarpHandle;

static bool protect_socket(int32_t socket, void *context)
{
    WarpHandle *handle = context;
    JNIEnv *env = NULL;
    bool attached = false;
    jint status = (*handle->vm)->GetEnv(handle->vm, (void **)&env, JNI_VERSION_1_6);
    if (status == JNI_EDETACHED) {
        if ((*handle->vm)->AttachCurrentThread(handle->vm, &env, NULL) != JNI_OK) {
            return false;
        }
        attached = true;
    } else if (status != JNI_OK) {
        return false;
    }
    jboolean protected = (*env)->CallBooleanMethod(env, handle->protector, handle->protect, (jint)socket);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        protected = JNI_FALSE;
    }
    if (attached) {
        (*handle->vm)->DetachCurrentThread(handle->vm);
    }
    return protected == JNI_TRUE;
}

JNIEXPORT jlong JNICALL Java_org_amnezia_vpn_WarpTransport_nativeStart(
    JNIEnv *env, jobject self, jstring underlay, jstring protocol, jstring configuration)
{
    WarpHandle *handle = calloc(1, sizeof(WarpHandle));
    if (handle == NULL || (*env)->GetJavaVM(env, &handle->vm) != JNI_OK) {
        free(handle);
        return 0;
    }
    jclass type = (*env)->GetObjectClass(env, self);
    handle->protect = (*env)->GetMethodID(env, type, "protectSocket", "(I)Z");
    (*env)->DeleteLocalRef(env, type);
    if (handle->protect == NULL) {
        free(handle);
        return 0;
    }
    handle->protector = (*env)->NewGlobalRef(env, self);
    if (handle->protector == NULL) {
        free(handle);
        return 0;
    }
    const char *underlay_text = (*env)->GetStringUTFChars(env, underlay, NULL);
    const char *protocol_text = (*env)->GetStringUTFChars(env, protocol, NULL);
    const char *configuration_text = (*env)->GetStringUTFChars(env, configuration, NULL);
    handle->session = -1;
    if (underlay_text != NULL && protocol_text != NULL && configuration_text != NULL) {
        handle->session = amneziaWarpStart((char *)underlay_text, (char *)protocol_text,
                                          (char *)configuration_text, protect_socket, handle);
    }
    if (underlay_text != NULL) (*env)->ReleaseStringUTFChars(env, underlay, underlay_text);
    if (protocol_text != NULL) (*env)->ReleaseStringUTFChars(env, protocol, protocol_text);
    if (configuration_text != NULL) (*env)->ReleaseStringUTFChars(env, configuration, configuration_text);
    if (handle->session < 0) {
        (*env)->DeleteGlobalRef(env, handle->protector);
        free(handle);
        return 0;
    }
    return (jlong)(uintptr_t)handle;
}

JNIEXPORT jstring JNICALL Java_org_amnezia_vpn_WarpTransport_nativeConfiguration(JNIEnv *env, jobject self, jlong pointer)
{
    WarpHandle *handle = (WarpHandle *)(uintptr_t)pointer;
    if (handle == NULL) return NULL;
    char *configuration = amneziaWarpConfiguration(handle->session);
    if (configuration == NULL) return NULL;
    jstring result = (*env)->NewStringUTF(env, configuration);
    amneziaWarpFree(configuration);
    return result;
}

JNIEXPORT jint JNICALL Java_org_amnezia_vpn_WarpTransport_nativeState(JNIEnv *env, jobject self, jlong pointer)
{
    WarpHandle *handle = (WarpHandle *)(uintptr_t)pointer;
    return handle == NULL ? -1 : amneziaWarpState(handle->session);
}

JNIEXPORT jboolean JNICALL Java_org_amnezia_vpn_WarpTransport_nativeRebind(JNIEnv *env, jobject self, jlong pointer)
{
    WarpHandle *handle = (WarpHandle *)(uintptr_t)pointer;
    return handle != NULL && amneziaWarpRebind(handle->session) == 0;
}

JNIEXPORT void JNICALL Java_org_amnezia_vpn_WarpTransport_nativeStop(JNIEnv *env, jobject self, jlong pointer)
{
    WarpHandle *handle = (WarpHandle *)(uintptr_t)pointer;
    if (handle == NULL) return;
    amneziaWarpStop(handle->session);
    (*env)->DeleteGlobalRef(env, handle->protector);
    free(handle);
}
