#ifndef COMMON_NON_LOCKER_QUEUE_H_
#define COMMON_NON_LOCKER_QUEUE_H_

#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <list>

namespace {
const unsigned int QUEUE_SIZE = 64;
}

template <typename T>
class CQueue {
   public:
    CQueue() : pre_windex(0), windex(0), pre_rindex(0), rindex(0) {
        pthread_condattr_init(&condattr);
        pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC);

        pthread_mutex_init(&lock, NULL);
        pthread_cond_init(&has_item, &condattr);

        for (unsigned int i = 0; i < QUEUE_SIZE; ++i) m_queue[i] = NULL;
    }
    ~CQueue() {
        pthread_mutex_destroy(&lock);
        pthread_cond_destroy(&has_item);
        pthread_condattr_destroy(&condattr);
    }

    //新元素入队列，保证一定可以入队，如果当前队列已满，则不断尝试
    void EnQueue(T* new_item) {
        unsigned int cur_pre_windex, new_index;

        //申请一个空位
        bool getslot_suc = false;
        do {
            //获取当前的预写位置 并 需要更新的预写位置new_index
            cur_pre_windex = pre_windex;
            new_index = (cur_pre_windex + 1) & (max_size - 1);

            //判断文件是否已满
            bool is_full = (new_index == rindex);

            //未满则申请一个空位，即申请一个预写位置
            if (is_full == false) {
                //返回true，表明更新预写位置成功，即更新前的位置就在这个线程可见其他线程不可见
                getslot_suc = __sync_bool_compare_and_swap(
                    &pre_windex, cur_pre_windex, new_index);
            }

        } while (getslot_suc == false);

        //填入数据
        m_queue[cur_pre_windex] = new_item;

        //发布最新数据，使得windex与当前线程更新的pre_windex保持一致，同时使读线程对最新数据可见
        bool public_suc = false;
        do {
            public_suc = __sync_bool_compare_and_swap(&windex, cur_pre_windex,
                                                      new_index);
        } while (public_suc == false);
    }

    //批量出队列，读取元素，可能队列没有元素，读取到空值
    void DeQueue(std::list<T*>& v) {
        unsigned int cur_pre_rindex, cur_windex;

        //获取当前预读位置 和 写位置
        cur_pre_rindex = pre_rindex;
        cur_windex = windex;

        //判断队列是否为空cur_pre_rindex == cur_windex表明队列为空
        bool is_empty = true;

        if (cur_pre_rindex != cur_windex) {
            //如果队列不为空，尝试获取将所有的有效元素，即将预读位置更新到写位置
            is_empty = !(__sync_bool_compare_and_swap(
                &pre_rindex, cur_pre_rindex, cur_windex));
        }

        //如果获取到了所有的元素，则进行读取，并清理队列
        if (is_empty == false) {
            //|||||||cur_pre_rindex|||||||cur_windex||||||
            //--------------------********----------------
            if (cur_pre_rindex < cur_windex) {
                for (unsigned int i = cur_pre_rindex; i < cur_windex; i++) {
                    v.push_back(m_queue[i]);
                    m_queue[i] = NULL;
                }
            }

            //|||||||cur_windex|||||||cur_pre_rindex||||||
            //*******------------------------------*******
            if (cur_pre_rindex > cur_windex) {
                for (unsigned int i = cur_pre_rindex; i < max_size; i++) {
                    v.push_back(m_queue[i]);
                    m_queue[i] = NULL;
                }

                for (unsigned int i = 0; i < cur_windex; i++) {
                    v.push_back(m_queue[i]);
                    m_queue[i] = NULL;
                }
            }

            //发布读取结束，更新rindex位置，只会更新到当前线程申请的预读空间大小位置
            bool release_suc = false;
            do {
                release_suc = __sync_bool_compare_and_swap(
                    &rindex, cur_pre_rindex, cur_windex);
            } while (release_suc == false);
        }
    }

    //对队列拍摄快照，不一定准确，可能读取的元素存在NULL，也可能还有部分元素未读取到
    //但是可以保证的是：读取为NULL的元素已经被其他线程拿去处理了，部分未读到的元素是
    //是在拍快照的这一刻之后加入队列的。（谨慎使用）
    void SnapShot(std::list<T*>& v) {
        unsigned int cur_rinxex = rindex;
        unsigned int cur_windex = windex;
        //|||||||cur_pre_rindex|||||||cur_windex||||||
        //--------------------********----------------
        if (cur_rinxex < cur_windex) {
            for (unsigned int i = cur_rinxex; i < cur_windex; i++) {
                v.push_back(m_queue[i]);
            }
        }

        //|||||||cur_windex|||||||cur_pre_rindex||||||
        //*******------------------------------*******
        if (rindex > windex) {
            for (unsigned int i = cur_rinxex; i < max_size; i++) {
                v.push_back(m_queue[i]);
            }

            for (unsigned int i = 0; i < cur_windex; i++) {
                v.push_back(m_queue[i]);
            }
        }
    }

    //判断队列是否为空，也是一个快照概念，只是调用这一刻的状态
    bool IsEmpty() { return windex == rindex; }

    //判断队列是否为满，也是一个快照概念，只是调用这一刻的状态
    bool IsFull() {
        unsigned int wi, ri;
        wi = (windex + 1) & (max_size - 1);
        ri = rindex;

        return wi == ri;
    }

    //获取队列大小，也是一个快照概念，只是调用这一刻的状态
    unsigned int size() {
        unsigned int wi, ri, len;
        wi = windex;
        ri = rindex;

        if (wi == ri) len = 0;

        if (wi > ri) len = wi - ri;

        if (wi < ri) len = wi + max_size - ri;

        return len;
    }

    void wait() {
        pthread_mutex_lock(&lock);
        pthread_cond_wait(&has_item, &lock);
        pthread_mutex_unlock(&lock);
    }

    // wait time ms
    void wait(long timeout) {
        pthread_mutex_lock(&lock);

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);

        long wait_time = ts.tv_nsec + (timeout * 1000000);
        ts.tv_sec += (wait_time / 1000000000);
        ts.tv_nsec = (wait_time % 1000000000);

        pthread_cond_timedwait(&has_item, &lock, &ts);

        pthread_mutex_unlock(&lock);
    }

    void signal() {
        pthread_mutex_lock(&lock);
        pthread_cond_broadcast(&has_item);
        pthread_mutex_unlock(&lock);
    }

    void set_maxsize(unsigned int size) {
        if (size <= 0 || size > QUEUE_SIZE)
            max_size = QUEUE_SIZE;
        else
            max_size = size;
    }

    unsigned int get_maxsize() { return max_size; }

   private:
    T* m_queue[QUEUE_SIZE];
    unsigned int max_size;
    volatile unsigned int pre_windex;  // 1.1写操作必须先更新这个值
    volatile unsigned int windex;  // 1.2写完数据后再更新这个值对外发布

    volatile unsigned int pre_rindex;  // 2.1读操作必须先更新这个值
    volatile unsigned int rindex;  // 2.2读完之后再更新这个值对外发布

   public:
    // 对外公开的锁和条件变量，可用于等待队列非空
    pthread_condattr_t condattr;
    pthread_mutex_t lock;
    pthread_cond_t has_item;
};

#endif /* COMMON_NON_LOCKER_QUEUE_H_ */
