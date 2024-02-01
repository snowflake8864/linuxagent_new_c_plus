#include "CKernelMsg.h"


CKernelMsgSendCmd::CKernelMsgSendCmd() { m_attrs.resize(__NL_POLICY_ATTR_MAX); }

const char* CKernelMsgSendCmd::GetAttrMsg(NL_POLICY_ATTR attr_index,
                                          size_t& msg_len) {
    if (attr_index >= NL_POLICY_ATTR_UNSPEC &&
        attr_index < __NL_POLICY_ATTR_MAX) {
        msg_len = m_attrs[attr_index].second;
        return m_attrs[attr_index].first;
    }
    return NULL;
}

int CKernelMsgSendCmd::SetAttrMsg(NL_POLICY_ATTR attr_index, const char* msg,
                                  size_t msg_len) {
    if (attr_index >= NL_POLICY_ATTR_UNSPEC &&
        attr_index < __NL_POLICY_ATTR_MAX) {
        m_attrs[attr_index].second = msg_len;
        m_attrs[attr_index].first = msg;
        return 0;
    }
    return -1;
}

void CKernelMsgSendCmd::Clear() {
    m_attrs.clear();
    m_attrs.resize(__NL_POLICY_ATTR_MAX);
}
