#ifndef TIMER_INTERFACE_ITIMER_HPP_
#define TIMER_INTERFACE_ITIMER_HPP_

#include <string>
#include <tr1/functional>
#include "ASFramework/ASUnknown.h"

typedef std::tr1::function<int()> TimerHandler;

struct TimerHandlerConf {
    long start_time;      //开始时间，即注册之后延迟多久开始，秒
    long cycle_time;      //周期时间，秒，需大于等于m_nClickTime
    long repeat_count;    //执行次数，-1表示循环执行，>0则执行对应次数
    TimerHandler handler; //执行函数
                          // bind
                          // handler = std::tr1::bind(&classname::function, &object, param, ...)
    TimerHandlerConf() : start_time(-1), cycle_time(-1), repeat_count(-1), handler(NULL) {}
};

class ITimer : public IASUnknown {
  public:
    virtual ~ITimer(){};

  public:
    virtual int RegisterEvent(TimerHandlerConf stConf, const std::string &strTimerName) = 0;
    virtual int UnRegisterEvent(const std::string &strTimerName) = 0;
};

#endif /* TIMER_INTERFACE_ITIMER_HPP_ */
