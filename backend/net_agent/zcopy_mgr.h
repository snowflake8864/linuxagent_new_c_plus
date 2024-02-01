#ifndef ZCOPY_MGRH
#define ZCOPY_MGRH

class CZcopy_MGR {
public:
    CZcopy_MGR();
        struct osec_network_report *getInNetLogAuditData(int idx);
        struct osec_network_report *getOutNetLogAuditData(int idx);
        struct osec_openport_report *getOpenPortLogAuditData(int idx);
        struct osec_dns_report *getDnsLogAuditData(int idx);
        ~CZcopy_MGR();
private:
        int uio_fd;
        int in_netlog_audit_size_fd;
        int in_netlog_audit_addr_fd;
        int out_netlog_audit_size_fd;
        int out_netlog_audit_addr_fd;
        int openport_netlog_audit_size_fd;
        int openport_netlog_audit_addr_fd;
        int dns_netlog_audit_size_fd;
        int dns_netlog_audit_addr_fd;
        void *in_netlog_cir_buffer;
        void *out_netlog_cir_buffer;
        void *openport_netlog_cir_buffer;
        void *dns_netlog_cir_buffer;
        size_t  in_netlog_audit_size;
        void *in_netlog_audit_addr;
        size_t out_netlog_audit_size;
        void *out_netlog_audit_addr;
        size_t openport_netlog_audit_size;
        void *openport_netlog_audit_addr;
        size_t dns_netlog_audit_size;
        void *dns_netlog_audit_addr;
        unsigned int in_netlog_audit_total_count;
        unsigned int out_netlog_audit_total_count;
        unsigned int openport_netlog_audit_total_count;
        unsigned int dns_netlog_audit_total_count;
public:        
        bool out_netlog_audit_succeed;
        bool in_netlog_audit_succeed;
        bool openport_netlog_audit_succeed;
        bool dns_netlog_audit_succeed;
};

#endif 
