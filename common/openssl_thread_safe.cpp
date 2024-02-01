#include "openssl_thread_safe.h"
#include <tr1/memory>
#include <pthread.h>
#include "openssl/crypto.h"

namespace openssl_thread_safe{

static pthread_mutex_t *lock_cs = NULL;
static bool first_call = true;

static void LockingCallback(int mode, int type, const char *file, int line) {
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(lock_cs[type]));
    } else {
        pthread_mutex_unlock(&(lock_cs[type]));
    }
}

static void ThreadID(CRYPTO_THREADID *tid) {
    CRYPTO_THREADID_set_numeric(tid, (unsigned long)pthread_self());
}

static void ThreadSafeSetup() {
    lock_cs = new pthread_mutex_t[CRYPTO_num_locks()];
    for (int i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&(lock_cs[i]), NULL);
    }
    CRYPTO_THREADID_set_callback(ThreadID);
    CRYPTO_set_locking_callback(LockingCallback);
}

static void ThreadSafeCleanup() {
    CRYPTO_set_locking_callback(NULL);
    for (int i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_destroy(&(lock_cs[i]));
    }
    delete[] lock_cs;
    lock_cs = NULL;
    //_sync_val_compare_and_swap(&first_call, false, true);
}

static void SmartHandleDeleter(FThreadSafeCleanup *thread_safe_cleanup) {
    if (thread_safe_cleanup != NULL) thread_safe_cleanup();
}

SmartHandle GetThreadSafeSmartHandle() {
    if (__sync_val_compare_and_swap(&first_call, true, false)){
        ThreadSafeSetup();
        return SmartHandle(ThreadSafeCleanup, SmartHandleDeleter);
    }
    return SmartHandle(static_cast<FThreadSafeCleanup *>(NULL),
                       SmartHandleDeleter);
}

}