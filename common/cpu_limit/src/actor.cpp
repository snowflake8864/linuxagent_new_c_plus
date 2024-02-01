#include "cpu_limit/include/actor.h"
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include "log/log.h"

Actor::Actor():m_pCallBack(NULL) {}

Actor::~Actor() {}

long Actor::StartUp(IActorCallBack* pCallBack, bool bInit) {
    long lRetCode = -1;

    m_pCallBack = pCallBack;
    m_bInit = bInit;

    lRetCode = Activate();

    return lRetCode;
}

long Actor::Stop() {
    return DeActivate();
}

bool Actor::IsActive() {
    return (m_pThreadId == pthread_self());
}

long Actor::Activate() {
    if (0 != pthread_attr_init(&m_pAttr)) {
        LOG_ERROR("Activate's pthread_attr_init failed");
        return -1;
    }

    if (0 != pthread_attr_setdetachstate(&m_pAttr, PTHREAD_CREATE_JOINABLE)) {
        LOG_ERROR("Acivate's pthread_attr_init failed");
        return -1;
    }

    if (0 == pthread_create(&m_pThreadId, &m_pAttr, OnActivate, this)) {
        LOG_DEBUG("success to create cpulimit thread");
    } else {
        LOG_ERROR("failed to create cpulimit thread");
        return -1;
    }

    return 1;
}

long Actor::DeActivate() {
    //默认线程是可以取消并且同步取消（需等到取消点退出）
    if (0 != pthread_cancel(m_pThreadId)) {
        LOG_ERROR("DeActivate's pthread_cancel failed");
        return -1;
    }
    pthread_join(m_pThreadId, NULL);
    LOG_INFO("cpulimit thread exit");
    return 1;
}

void* Actor::OnActivate(void* lParam) {
    Actor* pThis = (Actor*)lParam;
    pThis->m_pCallBack->OnActivate(pThis);
    return NULL;
}
