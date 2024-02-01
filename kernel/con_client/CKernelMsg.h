#ifndef CKERNEL_MSK_H
#define CKERNEL_MSK_H
#include "IKernelConnector.h"
//#include <netlink/netlink.h>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>
#include "gnHead.h"


class CKernelMsgSendCmd : public IKernelMsg {
   public:
    CKernelMsgSendCmd();
    virtual ~CKernelMsgSendCmd(){};
    virtual const char* GetAttrMsg(NL_POLICY_ATTR attr_index, size_t& msg_len);

    void Clear();
    int SetAttrMsg(NL_POLICY_ATTR attr_index, const char* msg, size_t msg_len);

   private:
    std::vector<std::pair<const char*, size_t> > m_attrs;
};

#endif  // CKERNEL_MSK_H
