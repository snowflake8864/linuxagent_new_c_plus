#ifndef CPU_LIMIT_ACTOR_H
#define CPU_LIMIT_ACTOR_H

#include <pthread.h>

class Actor;

class IActorCallBack {
   public:
    virtual ~IActorCallBack(){};
    virtual void OnActivate(Actor* pActor) = 0;
};

class Actor {
  public:
    Actor();
    virtual ~Actor();

    long StartUp(IActorCallBack* pCallBack, bool bInit = false);
    long Stop();

    bool IsActive();

  protected:
    long Activate();
    long DeActivate();

    static void* OnActivate(void* lParam);

  private:
    pthread_attr_t m_pAttr;
    pthread_t m_pThreadId;

    bool m_bInit;
    IActorCallBack* m_pCallBack;
};
#endif /* CPU_LIMIT_ACTOR_H */
