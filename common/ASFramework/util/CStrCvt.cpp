#include "CStrCvt.h"
#ifdef __linux__
// boost::mutex CStrCvt::m_sInstanceLock;

// int main(int argc, char ** argv){
//     std::string s = "1234";
//     std::wstring ws = CVT_S2WS(s, "");

//     std::cout << s << s.size() << std::endl;
//     std::wcout << ws << ws.size() << std::endl;

//     return 0;
// }

// const std::wstring CStrCvt::s2ws(const std::string& s, const std::string&
// name)
// {
//     boost::lock_guard<boost::mutex> lck(m_sInstanceLock);
//     std::locale sys_loc("");
//     std::ofstream ofs("cvt_buf");
//     ofs << s;
//     ofs.close();
//     std::wifstream wifs("cvt_buf");
//     wifs.imbue(sys_loc);
//     std::wstring wstr;
//     wifs >> wstr;
//     wifs.close();
//     ::unlink("cvt_buf");
//     return wstr;
// }

// const std::string CStrCvt::ws2s(const std::wstring& s, const std::string&
// name)
// {
//     boost::lock_guard<boost::mutex> lck(m_sInstanceLock);
//     std::locale sys_loc("");
//     std::wofstream wofs("cvt_buf");
//     wofs.imbue(sys_loc);
//     wofs << s;
//     wofs.close();
//     std::ifstream ifs("cvt_buf");
//     std::string str;
//     ifs >> str;
//     ifs.close();
//     ::unlink("cvt_buf");
//     return str;
// }
#endif