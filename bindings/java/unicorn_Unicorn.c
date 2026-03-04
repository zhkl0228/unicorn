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
static jclass jclassUnicornException;
static jclass jclassNumber;
static jclass jclassLong;
static jclass jclassMemRegion;

#define SEARCH_BPS_COUNT 8

KHASH_MAP_INIT_INT64(64, char)

struct unicorn_instance {
    uc_engine *eng;
    jboolean fastDebug;
    jint singleStep;
    uint64_t bps[SEARCH_BPS_COUNT];
    khash_t(64) *bps_map;
};

struct debugger_hook {
    uc_hook hh;
    jobject hook;
    struct unicorn_instance *inst;
};

static struct unicorn_instance *getInstance(JNIEnv *env, jobject self) {
   static jfieldID fid = 0;
   if (fid == 0) {
      jclass clazz = (*env)->GetObjectClass(env, self);
      fid = (*env)->GetFieldID(env, clazz, "eng", "J");
   }
   return (struct unicorn_instance *)(*env)->GetLongField(env, self, fid);
}

static void update_bps(struct unicorn_instance *inst) {
  int n = kh_size(inst->bps_map);
  if(n <= SEARCH_BPS_COUNT) {
    int idx = 0;
    for (khiter_t k = kh_begin(inst->bps_map); k < kh_end(inst->bps_map); k++) {
      if(kh_exist(inst->bps_map, k)) {
        uint64_t key = kh_key(inst->bps_map, k);
        inst->bps[idx++] = key;
      }
    }
  }
}

static inline bool hitBreakPoint(struct unicorn_instance *inst, int n, uint64_t address) {
    for(int i = 0; i < n; i++) {
        if(inst->bps[i] == address) {
            return true;
        }
    }
    return false;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    setFastDebug
 * Signature: (Z)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_setFastDebug
(JNIEnv *env, jobject obj, jboolean _fastDebug) {
    struct unicorn_instance *inst = getInstance(env, obj);
    inst->fastDebug = _fastDebug;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    setSingleStep
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_setSingleStep
(JNIEnv *env, jobject obj, jint _singleStep) {
    struct unicorn_instance *inst = getInstance(env, obj);
    inst->singleStep = _singleStep;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    addBreakPoint
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_addBreakPoint
(JNIEnv *env, jobject obj, jlong address) {
    struct unicorn_instance *inst = getInstance(env, obj);
    int ret;
    khiter_t k = kh_put(64, inst->bps_map, address, &ret);
    kh_value(inst->bps_map, k) = 1;
    update_bps(inst);
}

/*
 * Class:     unicorn_Unicorn
 * Method:    removeBreakPoint
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_removeBreakPoint
(JNIEnv *env, jobject obj, jlong address) {
    struct unicorn_instance *inst = getInstance(env, obj);
    khiter_t k = kh_get(64, inst->bps_map, address);
    if (k != kh_end(inst->bps_map)) {
        kh_del(64, inst->bps_map, k);
        update_bps(inst);
    }
}

static void cb_debugger(uc_engine *eng, uint64_t address, uint32_t size, void *user_data) {
    struct debugger_hook *dh = (struct debugger_hook *)user_data;
    struct unicorn_instance *inst = dh->inst;
    JNIEnv *env;
    int n;
    
    if((inst->singleStep > 0 && --inst->singleStep == 0) || ((n = kh_size(inst->bps_map)) > 0 && (n > SEARCH_BPS_COUNT ? (kh_get(64, inst->bps_map, address) != kh_end(inst->bps_map)) : hitBreakPoint(inst, n, address)))) {
        (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
        (*env)->CallVoidMethod(env, dh->hook, onBreak, (jlong)address, (int)size);
        (*cachedJVM)->DetachCurrentThread(cachedJVM);
    } else if(inst->fastDebug != JNI_TRUE) {
        (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
        (*env)->CallVoidMethod(env, dh->hook, onCode, (jlong)address, (int)size);
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
   const char *msg = uc_strerror(err);
   (*env)->ThrowNew(env, jclassUnicornException, msg);
}

/*
 * Class:     unicorn_Unicorn
 * Method:    reg_write_num
 * Signature: (ILjava/lang/Number;)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_reg_1write_1num
  (JNIEnv *env, jobject self, jint regid, jobject value) {
   uc_engine *eng = getInstance(env, self)->eng;

   static jmethodID longValue = 0;
   if(longValue == 0) {
      longValue = (*env)->GetMethodID(env, jclassNumber, "longValue", "()J");
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
   uc_engine *eng = getInstance(env, self)->eng;

   jlong longVal;
   uc_err err = uc_reg_read(eng, regid, &longVal);
   if (err != UC_ERR_OK) {
      throwException(env, err);
      return NULL;
   }

   static jmethodID cons = 0;
   if(cons == 0) {
      cons = (*env)->GetMethodID(env, jclassLong, "<init>", "(J)V");
   }
   jobject result = (*env)->NewObject(env, jclassLong, cons, longVal);
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
      return 0;
   }
   uc_set_tb_flush_on_finish(eng, false);

   struct unicorn_instance *inst = calloc(1, sizeof(struct unicorn_instance));
   inst->eng = eng;
   inst->fastDebug = JNI_TRUE;
   inst->bps_map = kh_init(64);
   return (jlong)inst;
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
   struct unicorn_instance *inst = getInstance(env, self);
   uc_err err = uc_close(inst->eng);
   if (inst->bps_map != NULL) {
      kh_destroy(64, inst->bps_map);
   }
   free(inst);
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
   uc_engine *eng = getInstance(env, self)->eng;
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
   uc_engine *eng = getInstance(env, self)->eng;
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
   uc_engine *eng = getInstance(env, self)->eng;
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
   uc_engine *eng = getInstance(env, self)->eng;
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

   uc_engine *eng = getInstance(env, self)->eng;
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
   uc_engine *eng = getInstance(env, self)->eng;

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
   uc_engine *eng = getInstance(env, self)->eng;

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
   uc_engine *eng = getInstance(env, self)->eng;

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
    struct unicorn_instance *inst = (struct unicorn_instance *)eng;
    uc_hook hh = 0;
    uc_err err = UC_ERR_OK;
    uint64_t begin = (uint64_t) arg1;
    uint64_t end = (uint64_t) arg2;
    
    jobject data = (*env)->NewGlobalRef(env, hook);
    switch (type) {
       case UC_HOOK_CODE:
          err = uc_hook_add(inst->eng, &hh, (uc_hook_type)type, cb_hookcode_new, data, begin, end);
          break;
       case UC_HOOK_BLOCK:
          err = uc_hook_add(inst->eng, &hh, (uc_hook_type)type, cb_hookblock_new, data, begin, end);
          break;
       case UC_HOOK_MEM_READ:
          err = uc_hook_add(inst->eng, &hh, (uc_hook_type)type, cb_hookmem_new, data, begin, end);
          break;
       case UC_HOOK_MEM_WRITE:
          err = uc_hook_add(inst->eng, &hh, (uc_hook_type)type, cb_hookmem_new, data, begin, end);
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
    struct unicorn_instance *inst = (struct unicorn_instance *)eng;
    uint64_t begin = (uint64_t) arg1;
    uint64_t end = (uint64_t) arg2;
    
    struct debugger_hook *dh = malloc(sizeof(struct debugger_hook));
    dh->hh = 0;
    dh->hook = (*env)->NewGlobalRef(env, hook);
    dh->inst = inst;
    
    uc_err err = uc_hook_add(inst->eng, &dh->hh, UC_HOOK_CODE, cb_debugger, dh, begin, end);
    if (err != UC_ERR_OK) {
      (*env)->DeleteGlobalRef(env, dh->hook);
      free(dh);
      throwException(env, err);
      return 0;
    }
    return (jlong)dh;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    registerHook
 * Signature: (JILunicorn/Unicorn/NewHook;)J
 */
JNIEXPORT jlong JNICALL Java_unicorn_Unicorn_registerHook__JILunicorn_Unicorn_NewHook_2
(JNIEnv *env, jclass clz, jlong eng, jint type, jobject hook) {
    struct unicorn_instance *inst = (struct unicorn_instance *)eng;
    uc_hook hh = 0;
    uc_err err = UC_ERR_OK;
    
    jobject data = (*env)->NewGlobalRef(env, hook);
    switch (type) {
       case UC_HOOK_INTR:
          err = uc_hook_add(inst->eng, &hh, (uc_hook_type)type, cb_hookintr_new, data, 1, 0);
          break;
       case UC_HOOK_MEM_FETCH_UNMAPPED:
       case UC_HOOK_MEM_READ_UNMAPPED:
       case UC_HOOK_MEM_WRITE_UNMAPPED:
       case UC_HOOK_MEM_FETCH_PROT:
       case UC_HOOK_MEM_READ_PROT:
       case UC_HOOK_MEM_WRITE_PROT:
          err = uc_hook_add(inst->eng, &hh, (uc_hook_type)type, cb_eventmem_new, data, 1, 0);
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
   uc_engine *eng = getInstance(env, self)->eng;

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
   uc_engine *eng = getInstance(env, self)->eng;

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
   uc_engine *eng = getInstance(env, self)->eng;
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
   uc_engine *eng = getInstance(env, self)->eng;

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
   uc_engine *eng = getInstance(env, self)->eng;

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
   uc_engine *eng = getInstance(env, self)->eng;

   uc_mem_region *regions = NULL;
   uint32_t count = 0;
   uint32_t i;

   uc_err err = uc_mem_regions(eng, &regions, &count);
   if (err != UC_ERR_OK) {
      throwException(env, err);
      return NULL;
   }
   jobjectArray result = (*env)->NewObjectArray(env, (jsize)count, jclassMemRegion, NULL);
   static jmethodID cons = 0;
   if(cons == 0) {
      cons = (*env)->GetMethodID(env, jclassMemRegion, "<init>", "(JJI)V");
   }
   for (i = 0; i < count; i++) {
      jobject mr = (*env)->NewObject(env, jclassMemRegion, cons, regions[i].begin, regions[i].end, regions[i].perms);
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
   uc_engine *eng = getInstance(env, self)->eng;
   uc_context *ctx;
   uc_err err = uc_context_alloc(eng, &ctx);
   if (err != UC_ERR_OK) {
      throwException(env, err);
      return 0;
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
   uc_engine *eng = getInstance(env, self)->eng;
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
   uc_engine *eng = getInstance(env, self)->eng;
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

    jclass exClass = (*env)->FindClass(env, "unicorn/UnicornException");
    if ((*env)->ExceptionCheck(env)) {
       return JNI_ERR;
    }
    jclassUnicornException = (*env)->NewGlobalRef(env, exClass);

    jclass numClass = (*env)->FindClass(env, "java/lang/Number");
    if ((*env)->ExceptionCheck(env)) {
       return JNI_ERR;
    }
    jclassNumber = (*env)->NewGlobalRef(env, numClass);

    jclass longClass = (*env)->FindClass(env, "java/lang/Long");
    if ((*env)->ExceptionCheck(env)) {
       return JNI_ERR;
    }
    jclassLong = (*env)->NewGlobalRef(env, longClass);

    jclass mrClass = (*env)->FindClass(env, "unicorn/MemRegion");
    if ((*env)->ExceptionCheck(env)) {
       return JNI_ERR;
    }
    jclassMemRegion = (*env)->NewGlobalRef(env, mrClass);
    
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
    
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *jvm, void *reserved) {
    JNIEnv *env;
    if (JNI_OK == (*jvm)->GetEnv(jvm, (void **)&env, JNI_VERSION_1_6)) {
       if (jclassUnicornException) {
          (*env)->DeleteGlobalRef(env, jclassUnicornException);
          jclassUnicornException = NULL;
       }
       if (jclassNumber) {
          (*env)->DeleteGlobalRef(env, jclassNumber);
          jclassNumber = NULL;
       }
       if (jclassLong) {
          (*env)->DeleteGlobalRef(env, jclassLong);
          jclassLong = NULL;
       }
       if (jclassMemRegion) {
          (*env)->DeleteGlobalRef(env, jclassMemRegion);
          jclassMemRegion = NULL;
       }
    }
}
