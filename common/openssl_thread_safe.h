#ifndef OPENSSL_THREAD_SAFE_H_
#define OPENSSL_THREAD_SAFE_H_
#include <tr1/memory>

namespace openssl_thread_safe{

typedef void FThreadSafeCleanup(void);
typedef std::tr1::shared_ptr<FThreadSafeCleanup> SmartHandle;
SmartHandle GetThreadSafeSmartHandle();

}

#endif /* OPENSSL_THREAD_SAFE_H_ */