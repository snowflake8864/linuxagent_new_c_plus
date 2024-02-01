#ifndef NF_RING_NFR_DEF
#define NF_RING_NFR_DEF

#ifdef __KERNEL__
    #include <linux/in.h>
    #include <linux/in6.h>
    #include <linux/netfilter.h>
    #include <linux/rtc.h>
    #include <linux/time.h>
    #include <linux/timex.h>
    #include <linux/types.h>
    #include <linux/version.h>
#else
    #include <netinet/in.h>
    #include <pthread.h>
    #include <stdint.h>
#endif

/* Watermark */
#define DEFAULT_MIN_PKT_QUEUED 128

#define RING_MAGIC
#define RING_MAGIC_VALUE 0x88

#define DEFAULT_BUCKET_LEN    128
#define DEFAULT_MIN_NUM_SLOTS 300

/* Set sockopt */
#define SO_ACTIVATE_RING           106
#define SO_DEACTIVATE_RING         107
#define SO_SHUTDOWN_RING           108
#define SO_RING_BUCKET_LEN         109 // 数据包捕获最大长度
#define SO_SET_POLL_WATERMARK      110
#define SO_ENABLE_RX_PACKET_BOUNCE 112
#define SO_CONSUME_PENDING_PKTS    113
#define SO_RING_MIN_NUM_SLOTS      114
#define SO_SOC_IP                  115 // for soc ipaddr
#define SO_RIP_LPORT_WHITELIST     116 // for remote ip local port whitelist
#define SO_SET_NFR_VERSION         117
#define SO_ADD_CUSTOM_PORT         118 // 添加自定义端口
#define SO_DEL_CUSTOM_PORT         119 // 移除自定义端口

/* Get sockopt */
#define SO_GET_PKT_HEADER_LEN 179
#define SO_GET_NFR_VERSION    180

#ifdef __KERNEL__
struct nfhook_fn_handle {
    u8 hooknum;
    u8 pf;
    int ring_id;
    struct net_device *in;
    struct net_device *out;
    struct sock *sk;
    void *net;
    void *state;
    void *okfn;
};
#endif

enum NFR_DATA_DIRECTION {
    NFR_DATA_DIR_UNSPEC = 0,
    NFR_DATA_DIR_IN,
    NFR_DATA_DIR_OUT,
    NFR_DATA_DIR_MAX,
};

enum NFR_VERSION {
    NFR_VERSION_UNSPEC = 0,
    NFR_VERSION_V1,
    NFR_VERSION_V2,
};

enum NFR_PACKET_OPE_RESULT {
    NFR_PACK_ACCPET = 0, // 放行该连接
    NFR_PACK_CONTINUE,   // 放行本次数据包
    NFR_PACK_DROP,       // 拦截该连接
};

// 应用层协议
enum NFR_APP_PROTOCOL {
    NFR_APP_PTL_PEND = 0,
    NFR_APP_PTL_HTTP,          // HTTP
    NFR_APP_PTL_HTTPS,         // HTTPS
    NFR_APP_PTL_TLS,           // TLS
    NFR_APP_PTL_FTP,           // FTP
    NFR_APP_PTL_FTPS,          // FTP + TLS
    NFR_APP_PTL_SMTP,          // SMTP
    NFR_APP_PTL_SMTPS,         // SMTP + TLS
    NFR_APP_PTL_SMB,           // SMB
    NFR_APP_PTL_CUSTOM = 0xfe, // 自定义
    NFR_APP_PTL_UNKNOWN = 0xff,
};

enum NFR_DATA_TYPE {
    NFR_DTYPE_UPSPEC = 0, // 未知包
    NFR_DTYPE_CONNET,     // 握手包
    NFR_DTYPE_DATA,       // 数据包
    NFR_DTYPE_CLOSED,     // 挥手包
    NFR_DTYPE_DATACLOSED, // 带数据的挥手包
};

typedef struct pack_header {
    uint32_t pid;      // 进程pid
    uint32_t protocol; // 传输层协议
    uint8_t family;    // ipv4/ipv6
    uint8_t dir;       // 数据方向 DATA_DIRECTION
    struct {
        uint8_t l5_ptl; // 应用层协议（不精准），APP_PROTOCOL
        uint8_t state;  // 1=first_data, 2=non first data, 3=tcp closed
        uint32_t hash;  // tcp hash
        uint32_t sport;
        uint32_t dport;
        union {
            struct in_addr in;
            struct in6_addr in6;
        } saddr, daddr;
        uint32_t payload; // 负载长度
    } tcp;
    uint32_t caplen; // 数据包长度
} pack_header_t __attribute__((aligned(4)));

#ifdef __KERNEL__
typedef struct nfr_tx_ctx {
    struct list_head list;
    // atomic_t ref_count;
    struct nfhook_fn_handle nf_handle;
    struct sk_buff *skb; /* Kernel only pointer */
    struct session *ss;
    uint8_t send_flag;
} nfr_tx_ctx_t;
#endif

typedef struct nfr_pkthdr {
    struct pack_header phdr;
    uint32_t user_ope; // PACKET_OPE_RESULT
#ifdef __KERNEL__
    nfr_tx_ctx_t *tx_ctx;
#endif
} nfr_pkthdr_t;

typedef enum { NFR_TX_KTHREAD, NFR_TX_TASKLET, NFR_TX_SYSCALL } tx_mode;

typedef struct nfring_tx_setting {
    uint8_t txnum;
    tx_mode txmode;
} nfring_tx_setting_t;

#endif /* NF_RING_NFR_DEF */
