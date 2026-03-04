/*

Java bindings for the Unicorn Emulator Engine

Copyright(c) 2015 Chris Eagle

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
version 2 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/

#include <sys/types.h>
#include "unicorn/platform.h"
#include <stdlib.h>
#include <string.h>
#include "khash.h"

#include <unicorn/unicorn.h>
#include "unicorn_Unicorn.h"

static jmethodID onBlock = 0;
static jmethodID onCode = 0;
static jmethodID onBreak = 0;
static jmethodID onRead = 0;
static jmethodID onWrite = 0;
static jmethodID onInterrupt = 0;
static jmethodID onMemEvent = 0;

static JavaVM* cachedJVM;

static jboolean fastDebug = JNI_TRUE;
static jint singleStep = 0;

/*
 * Class:     unicorn_Unicorn
 * Method:    setFastDebug
 * Signature: (Z)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_setFastDebug
(JNIEnv *env, jobject obj, jboolean _fastDebug) {
    fastDebug = _fastDebug;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    setSingleStep
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_setSingleStep
(JNIEnv *env, jobject obj, jint _singleStep) {
    singleStep = _singleStep;
}

#define SEARCH_BPS_COUNT 8
static uint64_t bps[SEARCH_BPS_COUNT];

KHASH_MAP_INIT_INT64(64, char)
khash_t(64) *bps_map = NULL;

static void update_bps() {
  int n = kh_size(bps_map);
  if(n <= SEARCH_BPS_COUNT) {
    int idx = 0;
    for (khiter_t k = kh_begin(bps_map); k < kh_end(bps_map); k++) {
      if(kh_exist(bps_map, k)) {
        uint64_t key = kh_key(bps_map, k);
        bps[idx++] = key;
      }
    }
  }
}

/*
 * Class:     unicorn_Unicorn
 * Method:    addBreakPoint
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_addBreakPoint
(JNIEnv *env, jobject obj, jlong address) {
    int ret;
    khiter_t k = kh_put(64, bps_map, address, &ret);
    kh_value(bps_map, k) = 1;
    update_bps();
}

/*
 * Class:     unicorn_Unicorn
 * Method:    removeBreakPoint
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_removeBreakPoint
(JNIEnv *env, jobject obj, jlong address) {
    khiter_t k = kh_get(64, bps_map, address);
    kh_del(64, bps_map, k);
    update_bps();
}

static inline bool hitBreakPoint(int n, uint64_t address) {
    for(int i = 0; i < n; i++) {
        if(bps[i] == address) {
            return true;
        }
    }
    return false;
}

static void cb_debugger(uc_engine *eng, uint64_t address, uint32_t size, void *user_data) {
    JNIEnv *env;
    int n;
    
    if((singleStep > 0 && --singleStep == 0) || ((n = kh_size(bps_map)) > 0 && (n > SEARCH_BPS_COUNT ? (kh_get(64, bps_map, address) != kh_end(bps_map)) : hitBreakPoint(n, address)))) {
        (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
        (*env)->CallVoidMethod(env, user_data, onBreak, (jlong)address, (int)size);
        (*cachedJVM)->DetachCurrentThread(cachedJVM);
    } else if(fastDebug != JNI_TRUE) {
        (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
        (*env)->CallVoidMethod(env, user_data, onCode, (jlong)address, (int)size);
        (*cachedJVM)->DetachCurrentThread(cachedJVM);
    }
}

static void cb_hookcode_new(uc_engine *eng, uint64_t address, uint32_t size, void *user_data) {
   JNIEnv *env;
   (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
   (*env)->CallVoidMethod(env, user_data, onCode, (jlong)address, (int)size);
   (*cachedJVM)->DetachCurrentThread(cachedJVM);
}

static void cb_hookblock_new(uc_engine *eng, uint64_t address, uint32_t size, void *user_data) {
   JNIEnv *env;
   (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
   (*env)->CallVoidMethod(env, user_data, onBlock, (jlong)address, (int)size);
   (*cachedJVM)->DetachCurrentThread(cachedJVM);
}

static void cb_hookmem_new(uc_engine *eng, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data) {
   JNIEnv *env;
   (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
   switch (type) {
      case UC_MEM_READ:
         (*env)->CallVoidMethod(env, user_data, onRead, (jlong)address, (int)size);
         break;
      case UC_MEM_WRITE:
         (*env)->CallVoidMethod(env, user_data, onWrite, (jlong)address, (int)size, (jlong)value);
         break;
      default:
         break;
   }
   (*cachedJVM)->DetachCurrentThread(cachedJVM);
}

static void cb_hookintr_new(uc_engine *eng, uint32_t intno, void *user_data) {
   JNIEnv *env;
   (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
   (*env)->CallVoidMethod(env, user_data, onInterrupt, (int)intno);
   (*cachedJVM)->DetachCurrentThread(cachedJVM);
}

static bool cb_eventmem_new(uc_engine *eng, uc_mem_type type,
                        uint64_t address, int size, int64_t value, void *user_data) {
   JNIEnv *env;
   (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
   jboolean res = (*env)->CallBooleanMethod(env, user_data, onMemEvent, (int)type, (jlong)address, (int)size, (jlong)value);
   (*cachedJVM)->DetachCurrentThread(cachedJVM);
   return res;
}

static void throwException(JNIEnv *env, uc_err err) {
   jclass clazz = (*env)->FindClass(env, "unicorn/UnicornException");
   if (err != UC_ERR_OK) {
      const char *msg = uc_strerror(err);
      (*env)->ThrowNew(env, clazz, msg);
   }
}

static uc_engine *getEngine(JNIEnv *env, jobject self) {
   static jfieldID fid = 0;
   if (fid == 0) {
      jclass clazz = (*env)->GetObjectClass(env, self);
      fid = (*env)->GetFieldID(env, clazz, "eng", "J");
   }
   return (uc_engine *)(*env)->GetLongField(env, self, fid);
}

/*
 * Class:     unicorn_Unicorn
 * Method:    reg_write_num
 * Signature: (ILjava/lang/Number;)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_reg_1write_1num
  (JNIEnv *env, jobject self, jint regid, jobject value) {
   uc_engine *eng = getEngine(env, self);

   static jmethodID longValue = 0;
   if(longValue == 0) {
       jclass clz = (*env)->FindClass(env, "java/lang/Number");
       if ((*env)->ExceptionCheck(env)) {
          return;
       }
      longValue = (*env)->GetMethodID(env, clz, "longValue", "()J");
   }
   jlong longVal = (*env)->CallLongMethod(env, value, longValue);
   uc_err err = uc_reg_write(eng, regid, &longVal);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

/*
 * Class:     unicorn_Unicorn
 * Method:    reg_read_num
 * Signature: (I)Ljava/lang/Number;
 */
JNIEXPORT jobject JNICALL Java_unicorn_Unicorn_reg_1read_1num
  (JNIEnv *env, jobject self, jint regid) {
   uc_engine *eng = getEngine(env, self);

   jclass clz = (*env)->FindClass(env, "java/lang/Long");
   if ((*env)->ExceptionCheck(env)) {
      return NULL;
   }

   jlong longVal;
   uc_err err = uc_reg_read(eng, regid, &longVal);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }

   static jmethodID cons = 0;
   if(cons == 0) {
      cons = (*env)->GetMethodID(env, clz, "<init>", "(J)V");
   }
   jobject result = (*env)->NewObject(env, clz, cons, longVal);
   if ((*env)->ExceptionCheck(env)) {
      return NULL;
   }
   return result;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    open
 * Signature: (II)J
 */
JNIEXPORT jlong JNICALL Java_unicorn_Unicorn_open
  (JNIEnv *env, jobject self, jint arch, jint mode) {
   uc_engine *eng = NULL;
   uc_err err = uc_open((uc_arch)arch, (uc_mode)mode, &eng);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
   uc_set_tb_flush_on_finish(eng, false);
   return (jlong)eng;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    version
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_unicorn_Unicorn_version
  (JNIEnv *env, jclass clz) {
    return (jint)uc_version(NULL, NULL);
}

/*
 * Class:     unicorn_Unicorn
 * Method:    arch_supported
 * Signature: (I)Z
 */
JNIEXPORT jboolean JNICALL Java_unicorn_Unicorn_arch_1supported
  (JNIEnv *env, jclass clz, jint arch) {
    return (jboolean)(uc_arch_supported((uc_arch)arch) != 0);
}

/*
 * Class:     unicorn_Unicorn
 * Method:    close
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_close
  (JNIEnv *env, jobject self) {
   uc_engine *eng = getEngine(env, self);
   uc_err err = uc_close(eng);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

/*
 * Class:     unicorn_Unicorn
 * Method:    query
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_unicorn_Unicorn_query
  (JNIEnv *env, jobject self, jint type) {
   uc_engine *eng = getEngine(env, self);
   size_t result;
   uc_err err = uc_query(eng, type, &result);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
   return (jint)result;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    errno
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_unicorn_Unicorn_errno
  (JNIEnv *env, jobject self) {
   uc_engine *eng = getEngine(env, self);
   return (jint)uc_errno(eng);
}

/*
 * Class:     unicorn_Unicorn
 * Method:    strerror
 * Signature: (I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_unicorn_Unicorn_strerror
  (JNIEnv *env, jclass clz, jint code) {
   const char *err = uc_strerror((int)code);
   jstring s = (*env)->NewStringUTF(env, err);
   return s;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    reg_write
 * Signature: (I[B)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_reg_1write
  (JNIEnv *env, jobject self, jint regid, jbyteArray value) {
   uc_engine *eng = getEngine(env, self);
   jbyte *array = (*env)->GetByteArrayElements(env, value, NULL);
   uc_err err = uc_reg_write(eng, (int)regid, (void *)array);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
   (*env)->ReleaseByteArrayElements(env, value, array, JNI_ABORT);
}

/*
 * Class:     unicorn_Unicorn
 * Method:    reg_read
 * Signature: (II)[B
 */
JNIEXPORT jbyteArray JNICALL Java_unicorn_Unicorn_reg_1read
  (JNIEnv *env, jobject self, jint regid, jint regsz) {
   uc_engine *eng = getEngine(env, self);
   jbyteArray regval = (*env)->NewByteArray(env, (jsize)regsz);
   jbyte *array = (*env)->GetByteArrayElements(env, regval, NULL);
   uc_err err = uc_reg_read(eng, (int)regid, (void *)array);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
   (*env)->ReleaseByteArrayElements(env, regval, array, 0);
   return regval;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    mem_write
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_mem_1write
  (JNIEnv *env , jobject self, jlong address, jbyteArray bytes) {

   uc_engine *eng = getEngine(env, self);
   jbyte *array = (*env)->GetByteArrayElements(env, bytes, NULL);
   jsize size = (*env)->GetArrayLength(env, bytes);
   uc_err err = uc_mem_write(eng, (uint64_t)address, array, (size_t)size);

   if (err != UC_ERR_OK) {
      throwException(env, err);
   }

   (*env)->ReleaseByteArrayElements(env, bytes, array, JNI_ABORT);
}

/*
 * Class:     unicorn_Unicorn
 * Method:    mem_read
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_unicorn_Unicorn_mem_1read
  (JNIEnv *env, jobject self, jlong address, jlong size) {
   uc_engine *eng = getEngine(env, self);

   jbyteArray bytes = (*env)->NewByteArray(env, (jsize)size);
   jbyte *array = (*env)->GetByteArrayElements(env, bytes, NULL);
   uc_err err = uc_mem_read(eng, (uint64_t)address, array, (size_t)size);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
   (*env)->ReleaseByteArrayElements(env, bytes, array, 0);
   return bytes;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    emu_start
 * Signature: (JJJJ)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_emu_1start
  (JNIEnv *env, jobject self, jlong begin, jlong until, jlong timeout, jlong count) {
   uc_engine *eng = getEngine(env, self);

   uc_err err = uc_emu_start(eng, (uint64_t)begin, (uint64_t)until, (uint64_t)timeout, (size_t)count);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

/*
 * Class:     unicorn_Unicorn
 * Method:    emu_stop
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_emu_1stop
  (JNIEnv *env, jobject self) {
   uc_engine *eng = getEngine(env, self);

   uc_err err = uc_emu_stop(eng);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

struct new_hook {
    uc_hook hh;
    jobject hook;
};

/*
 * Class:     unicorn_Unicorn
 * Method:    registerHook
 * Signature: (JIJJLunicorn/Unicorn/NewHook;)J
 */
JNIEXPORT jlong JNICALL Java_unicorn_Unicorn_registerHook__JIJJLunicorn_Unicorn_NewHook_2
(JNIEnv *env, jclass clz, jlong eng, jint type, jlong arg1, jlong arg2, jobject hook) {
    uc_hook hh = 0;
    uc_err err = UC_ERR_OK;
    uint64_t begin = (uint64_t) arg1;
    uint64_t end = (uint64_t) arg2;
    
    jobject data = (*env)->NewGlobalRef(env, hook);
    switch (type) {
       case UC_HOOK_CODE:
          err = uc_hook_add((uc_engine*)eng, &hh, (uc_hook_type)type, cb_hookcode_new, data, begin, end);
          break;
       case UC_HOOK_BLOCK:
          err = uc_hook_add((uc_engine*)eng, &hh, (uc_hook_type)type, cb_hookblock_new, data, begin, end);
          break;
       case UC_HOOK_MEM_READ:
          err = uc_hook_add((uc_engine*)eng, &hh, (uc_hook_type)type, cb_hookmem_new, data, begin, end);
          break;
       case UC_HOOK_MEM_WRITE:
          err = uc_hook_add((uc_engine*)eng, &hh, (uc_hook_type)type, cb_hookmem_new, data, begin, end);
          break;
    }
    if (err != UC_ERR_OK) {
      (*env)->DeleteGlobalRef(env, data);
      throwException(env, err);
      return 0;
    }
    
    struct new_hook *nh = malloc(sizeof(struct new_hook));
    nh->hh = hh;
    nh->hook = data;
    return (jlong)nh;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    registerDebugger
 * Signature: (JJJLunicorn/Unicorn/NewHook;)J
 */
JNIEXPORT jlong JNICALL Java_unicorn_Unicorn_registerDebugger
(JNIEnv *env, jclass clz, jlong eng, jlong arg1, jlong arg2, jobject hook) {
    uc_hook hh = 0;
    uint64_t begin = (uint64_t) arg1;
    uint64_t end = (uint64_t) arg2;
    
    jobject data = (*env)->NewGlobalRef(env, hook);
    uc_err err = uc_hook_add((uc_engine*)eng, &hh, UC_HOOK_CODE, cb_debugger, data, begin, end);
    if (err != UC_ERR_OK) {
      (*env)->DeleteGlobalRef(env, data);
      throwException(env, err);
      return 0;
    }
    
    struct new_hook *nh = malloc(sizeof(struct new_hook));
    nh->hh = hh;
    nh->hook = data;
    return (jlong)nh;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    registerHook
 * Signature: (JILunicorn/Unicorn/NewHook;)J
 */
JNIEXPORT jlong JNICALL Java_unicorn_Unicorn_registerHook__JILunicorn_Unicorn_NewHook_2
(JNIEnv *env, jclass clz, jlong eng, jint type, jobject hook) {
    uc_hook hh = 0;
    uc_err err = UC_ERR_OK;
    
    jobject data = (*env)->NewGlobalRef(env, hook);
    switch (type) {
       case UC_HOOK_INTR:
          err = uc_hook_add((uc_engine*)eng, &hh, (uc_hook_type)type, cb_hookintr_new, data, 1, 0);
          break;
       case UC_HOOK_MEM_FETCH_UNMAPPED:
       case UC_HOOK_MEM_READ_UNMAPPED:
       case UC_HOOK_MEM_WRITE_UNMAPPED:
       case UC_HOOK_MEM_FETCH_PROT:
       case UC_HOOK_MEM_READ_PROT:
       case UC_HOOK_MEM_WRITE_PROT:
          err = uc_hook_add((uc_engine*)eng, &hh, (uc_hook_type)type, cb_eventmem_new, data, 1, 0);
          break;
    }
    if (err != UC_ERR_OK) {
      (*env)->DeleteGlobalRef(env, data);
      throwException(env, err);
      return 0;
    }
    
    struct new_hook *nh = malloc(sizeof(struct new_hook));
    nh->hh = hh;
    nh->hook = data;
    return (jlong)nh;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    hook_del
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_hook_1del
  (JNIEnv *env, jobject self, jlong hh) {
   uc_engine *eng = getEngine(env, self);

   struct new_hook *nh = (struct new_hook *) hh;
   (*env)->DeleteGlobalRef(env, nh->hook);
   uc_err err = uc_hook_del(eng, nh->hh);
   free(nh);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

/*
 * Class:     unicorn_Unicorn
 * Method:    mem_map
 * Signature: (JJI)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_mem_1map
  (JNIEnv *env, jobject self, jlong address, jlong size, jint perms) {
   uc_engine *eng = getEngine(env, self);

   uc_err err = uc_mem_map(eng, (uint64_t)address, (size_t)size, (uint32_t)perms);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

/*
 * Class:     unicorn_Unicorn
 * Method:    mem_map_ptr
 * Signature: (JJI[B)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_mem_1map_1ptr
  (JNIEnv *env, jobject self, jlong address, jlong size, jint perms, jbyteArray block) {
   uc_engine *eng = getEngine(env, self);
   jbyte *array = (*env)->GetByteArrayElements(env, block, NULL);
   uc_err err = uc_mem_map_ptr(eng, (uint64_t)address, (size_t)size, (uint32_t)perms, (void*)array);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

/*
 * Class:     unicorn_Unicorn
 * Method:    mem_unmap
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_mem_1unmap
  (JNIEnv *env, jobject self, jlong address, jlong size) {
   uc_engine *eng = getEngine(env, self);

   uc_err err = uc_mem_unmap(eng, (uint64_t)address, (size_t)size);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

/*
 * Class:     unicorn_Unicorn
 * Method:    mem_protect
 * Signature: (JJI)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_mem_1protect
  (JNIEnv *env, jobject self, jlong address, jlong size, jint perms) {
   uc_engine *eng = getEngine(env, self);

   uc_err err = uc_mem_protect(eng, (uint64_t)address, (size_t)size, (uint32_t)perms);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

/*
 * Class:     unicorn_Unicorn
 * Method:    mem_regions
 * Signature: ()[Lunicorn/MemRegion;
 */
JNIEXPORT jobjectArray JNICALL Java_unicorn_Unicorn_mem_1regions
  (JNIEnv *env, jobject self) {
   uc_engine *eng = getEngine(env, self);

   uc_mem_region *regions = NULL;
   uint32_t count = 0;
   uint32_t i;

   uc_err err = uc_mem_regions(eng, &regions, &count);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
   jclass clz = (*env)->FindClass(env, "unicorn/MemRegion");
   if ((*env)->ExceptionCheck(env)) {
      return NULL;
   }
   jobjectArray result = (*env)->NewObjectArray(env, (jsize)count, clz, NULL);
   static jmethodID cons = 0;
   if(cons == 0) {
      cons = (*env)->GetMethodID(env, clz, "<init>", "(JJI)V");
   }
   for (i = 0; i < count; i++) {
      jobject mr = (*env)->NewObject(env, clz, cons, regions[i].begin, regions[i].end, regions[i].perms);
      (*env)->SetObjectArrayElement(env, result, (jsize)i, mr);
   }
   uc_free(regions);

   return result;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    context_alloc
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_unicorn_Unicorn_context_1alloc
  (JNIEnv *env, jobject self) {
   uc_engine *eng = getEngine(env, self);
   uc_context *ctx;
   uc_err err = uc_context_alloc(eng, &ctx);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
   return (jlong)(uint64_t)ctx;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_free
  (JNIEnv *env, jclass cls, jlong ctx) {
   uc_err err = uc_free((void *)ctx);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

/*
 * Class:     unicorn_Unicorn
 * Method:    context_save
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_context_1save
  (JNIEnv *env, jobject self, jlong ctx) {
   uc_engine *eng = getEngine(env, self);
   uc_err err = uc_context_save(eng, (uc_context*)ctx);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

/*
 * Class:     unicorn_Unicorn
 * Method:    context_restore
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_context_1restore
  (JNIEnv *env, jobject self, jlong ctx) {
   uc_engine *eng = getEngine(env, self);
   uc_err err = uc_context_restore(eng, (uc_context*)ctx);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

static JNINativeMethod s_methods[] = {
        {"registerHook",           "(JIJJLunicorn/Unicorn$NewHook;)J",          (void *) Java_unicorn_Unicorn_registerHook__JIJJLunicorn_Unicorn_NewHook_2 },
        {"registerHook",           "(JILunicorn/Unicorn$NewHook;)J",            (void *) Java_unicorn_Unicorn_registerHook__JILunicorn_Unicorn_NewHook_2 }
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *jvm, void *reserved) {
    JNIEnv *env;
    if (JNI_OK != (*jvm)->GetEnv(jvm, (void **)&env, JNI_VERSION_1_6)) {
       return JNI_ERR;
    }
    jclass clz = (*env)->FindClass(env, "unicorn/Unicorn");
    if ((*env)->ExceptionCheck(env)) {
       return JNI_ERR;
    }
    jclass newHookClass = (*env)->FindClass(env, "unicorn/Unicorn$NewHook");
    if ((*env)->ExceptionCheck(env)) {
       return JNI_ERR;
    }
    
    onBlock = (*env)->GetMethodID(env, newHookClass, "onBlock", "(JI)V");
    onCode = (*env)->GetMethodID(env, newHookClass, "onCode", "(JI)V");
    onBreak = (*env)->GetMethodID(env, newHookClass, "onBreak", "(JI)V");
    onRead = (*env)->GetMethodID(env, newHookClass, "onRead", "(JI)V");
    onWrite = (*env)->GetMethodID(env, newHookClass, "onWrite", "(JIJ)V");
    onInterrupt = (*env)->GetMethodID(env, newHookClass, "onInterrupt", "(I)V");
    onMemEvent = (*env)->GetMethodID(env, newHookClass, "onMemEvent", "(IJIJ)Z");
    
    int len = sizeof(s_methods) / sizeof(s_methods[0]);
    if ((*env)->RegisterNatives(env, clz, s_methods, len)) {
        return JNI_ERR;
    }
    
    cachedJVM = jvm;
    bps_map = kh_init(64);
    
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *jvm, void *reserved) {
    if(bps_map != NULL) {
       kh_destroy(64, bps_map);
    }
    bps_map = NULL;
}
