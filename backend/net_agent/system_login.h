#ifndef SYSTEMLOGIN_H_
#define SYSTEMLOGIN_H_

#include <string>
#include <vector>
#include <map>

typedef int CECode;

enum {
    UT_TYPE_BOOT = 0,
    UT_TYPE_SHUTDOWN,
    UT_TYPE_LOGIN,
    UT_TYPE_LOGOUT
};
typedef struct UTMP_INFO_S {
    int32_t type;                   //1, 登录 2, 注销 3, 开机 4, 关机
    int64_t time;               // 时间
    char user_name[32];         // 用户名
    char cmd_line[32];          // 登录命令行 tty pts
    char host[256];             // 远程登陆的主机名
    int result;
} UTMP_INFO_T;
void GetInfo(std::vector<UTMP_INFO_T> &vecUbmp, int type);
class CSystemLogin {
public:
    CSystemLogin();
    ~CSystemLogin();

public:
    void Clean();
    /*
    * 描述：获取当前系统登录、注销、开关机信息
    * 参数：info 用于接收获取到的数据内容; size用于接收获取到的数据个数; file_seek用于指定wtmp文件位置
    * 返回值：错误码
    */
    CECode GetWtmpInfo(UTMP_INFO_T **info, int *size, int *file_seek);
    /*
    * 描述：获取当前系统登录的用户信息
    * 参数：info 用于接收获取到的数据内容; size用于接收获取到的数据个数; file_seek用于指定utmp文件位置
    * 返回值：错误码
    */
    CECode GetUtmpInfo(UTMP_INFO_T **info, int *size, int *file_seek);
private:
    /*
    * 描述：处理一条wtmp记录
    * 参数：p_utent 指向一条wtmp记录
    * 返回值：无
    */
    void _DealWtmpInfo(struct utmp *p_utent);
    /*
    * 描述：处理一条utmp记录
    * 参数：p_utent 指向一条utmp记录
    * 返回值：无
    */
    void _DealUtmpInfo(struct utmp *p_utent);
    CECode _ProcSystemFile(UTMP_INFO_T **info, int *size, int *file_seek, bool isUtmp);

    uint32_t m_nInvalidAddr;
    //<ut_line, ut_user>， 登录时保存信息，当注销时如果ut_user为空从该map中查找匹配的ut_line得到ut_user
    std::map<std::string, std::string> m_mapLoginUser;
public:
    std::vector<UTMP_INFO_T> m_vecLogin;    //保存匹配到的wtmp信息
};

#endif //SYSTEMLOGIN_H_
