#include <string>

#ifndef __linux__
#include <boost/locale/encoding.hpp>
#include <boost/locale/generator.hpp>
#endif

#ifdef __linux__
    inline std::string CVT_WS2S(const std::wstring& buf, const std::string& char_set_name) {
        return std::string(buf.begin(), buf.end());
    }

    inline std::wstring CVT_S2WS(const std::string& buf, const std::string& char_set_name) {
        return std::wstring(buf.begin(), buf.end());
    }

#else
	#define CVT_S2WS(buf, char_set_name)  boost::locale::conv::to_utf<wchar_t>(buf, char_set_name)
	#define CVT_WS2S(buf, char_set_name)  boost::locale::conv::from_utf(buf, char_set_name)
#endif

