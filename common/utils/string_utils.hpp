#ifndef UTILS_STRING_UTILS_H_
#define UTILS_STRING_UTILS_H_

#include <errno.h>
#include <stdio.h>
#include <algorithm>
#include <string>
#include <sstream>
#include <tr1/memory>
#include "iconv.h"

namespace string_utils {
inline bool ToInt(const std::string& s, int& i) {
    std::stringstream ss;
    ss << s;
    ss >> i;
    return true;
}

inline int Oct2Int(const std::string& oct_str) {
    int iValue;
    ::sscanf(oct_str.c_str(), "%o", &iValue);
    return iValue;
}

inline int Hex2Int(const std::string& hex_str) {
    int iValue;
    ::sscanf(hex_str.c_str(), "%x", &iValue);
    return iValue;
}

inline std::string OctInt2String(const int ivalue) {
    char buf[128] = {0};
    ::sprintf(buf, "%o", ivalue);
    return std::string(buf);
}

inline std::string ToString(int i) {
    std::string strvalue;
    std::stringstream ss;
    ss << i;
    ss >> strvalue;
    return strvalue;
}

inline std::string ToStringDouble(double i) {
    std::string strvalue;
    std::stringstream ss;
    ss << i;
    ss >> strvalue;
    return strvalue;
}

inline std::string& Trim(std::string& text) {
     if (!text.empty()) {
         text.erase(0, text.find_first_not_of(" \n\r\t"));
         text.erase(text.find_last_not_of(" \n\r\t") + 1);
     }
     return text;
}

inline std::string& Trim(std::string& text, const std::string& space_character_set) {
     if (!text.empty()) {
         text.erase(0, text.find_first_not_of(space_character_set));
         text.erase(text.find_last_not_of(space_character_set) + 1);
     }
     return text;
}

inline std::string& TrimLeft(std::string& text) {
     if (!text.empty()) {
         text.erase(0, text.find_first_not_of(" \n\r\t"));
     }
     return text;
}

inline std::string& TrimLeft(std::string& text, const std::string& space_character_set) {
     if (!text.empty()) {
         text.erase(0, text.find_first_not_of(space_character_set));
     }
     return text;
}

inline std::string& TrimRight(std::string& text) {
     if (!text.empty()) {
         text.erase(text.find_last_not_of(" \n\r\t") + 1);
     }
     return text;
}

inline std::string& TrimRight(std::string& text, const std::string& space_character_set) {
     if (!text.empty()) {
         text.erase(text.find_last_not_of(space_character_set) + 1);
     }
     return text;
}

inline std::string& ToUpper(std::string& s) {
    transform(s.begin(), s.end(), s.begin(), (int (*)(int))toupper);
    return s;
}

inline std::string& ToLower(std::string& s) {
    transform(s.begin(), s.end(), s.begin(), (int (*)(int))tolower);
    return s;
}

inline bool IEquals(const std::string& ls, const std::string& rs) {
    return (ls == rs);
}

inline std::string JoinPath(const std::string& ls, const std::string& rs) {
    std::string left_string = ls, right_string = rs;
    return Trim(left_string) + '/' + Trim(right_string);
}

enum REPLACE_TYPE {
    REPLACE_NORMAL,
    REPLACE_RECURSE,
};

template <typename T>
T& ReplaceSeq(T& input, const T& old_seq, const T& new_seq,
              REPLACE_TYPE replace_type = REPLACE_NORMAL) {
    typename T::iterator cur_pos = input.begin();
    while (cur_pos != input.end()) {
        typename T::iterator find_pos =
            std::search(cur_pos, input.end(), old_seq.begin(), old_seq.end());
        if (find_pos == input.end()) {
            break;
        }
        find_pos = input.erase(find_pos, find_pos + old_seq.size());
        input.insert(find_pos, new_seq.begin(), new_seq.end());
        cur_pos = find_pos;
        if (replace_type == REPLACE_NORMAL) {
            cur_pos += new_seq.size();
        }
    }
    return input;
}

inline std::string& Replace(std::string& input, const std::string& old_str,
                            const std::string& new_str,
                            REPLACE_TYPE replace_type = REPLACE_NORMAL) {
    return ReplaceSeq(input, old_str, new_str, replace_type);
}

inline std::string& FormatPathSlash(std::string& path) {
    Replace(path, "/./", "/", REPLACE_RECURSE);
    Replace(path, "//", "/", REPLACE_RECURSE);
    return path;
}

template <typename T>
void Split(T& string_container, const std::string& s_to_split,
           const std::string& token) {
    string_container.clear();
    size_t p = std::string::npos, pp = 0;
    bool bFind = false;
    while ((p = s_to_split.find(token, pp)) != std::string::npos) {
        bFind = true;
        std::string s = s_to_split.substr(pp, p - pp);
        Trim(s);
        if (!s.empty()) string_container.push_back(s);
        while (s_to_split.substr(p + token.size(), token.size()) == token) {
            p = p + token.size();
            if (p >= (s_to_split.size() - token.size())) break;
        }
        pp = p + token.size();
    }
    if ((pp != 0 && pp < s_to_split.size()) || (bFind == false)) {
        std::string s = s_to_split.substr(pp);
        Trim(s);
        if (!s.empty()) string_container.push_back(s);
    }
}

static inline void IconvDeleter(iconv_t* iconv_point) { iconv_close(*iconv_point); }

typedef std::tr1::shared_ptr<char> EncodingConvertResult;
static inline EncodingConvertResult EncodingConvert(char* in, size_t in_bytes,
                                      const std::string& from_format,
                                      const std::string& to_format,
                                      size_t& out_bytes) {
    out_bytes = 0;
    iconv_t conv_open_ret = iconv_open(to_format.c_str(), from_format.c_str());
    if (conv_open_ret == (iconv_t)-1) {
        return EncodingConvertResult();
    }
    std::tr1::shared_ptr<iconv_t> conv_handle(&conv_open_ret, IconvDeleter);

    size_t in_left = in_bytes;
    size_t out_size = in_bytes * 6;  // UTF8 最多使用6个bytes表示一个字符
    size_t out_left = out_size;
    char* out_calloc_ret = (char*)calloc(1, out_left);
    if (out_calloc_ret == NULL) {
        return EncodingConvertResult();
    }
    EncodingConvertResult out(out_calloc_ret, free);
    size_t converted = iconv(conv_open_ret, &in, &in_left, &out_calloc_ret, &out_left);

    if (converted == (size_t)-1) {
        return EncodingConvertResult();
    }
    out_bytes = out_size - out_left;
    return out;
}

}

#endif  /* UTILS_STRING_UTILS_H_ */
