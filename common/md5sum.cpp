#include "md5sum.h"
#include "openssl/md5.h"

namespace md5sum {

using namespace std;

/* Return Calculated raw result(always little-endian), the size is always 16 */
void md5bin(const void* dat, size_t len, unsigned char out[16]) {
    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, dat, len);
    MD5_Final(out, &c);
}

static char hb2hex(unsigned char hb) {
    hb = hb & 0xF;
    return hb < 10 ? '0' + hb : hb - 10 + 'a';
}

string md5file(const char* filename) {
    FILE* file = fopen(filename, "rb");
    string res;
    if (file != NULL) {
        res = md5file(file);
        fclose(file);
    }
    return res;
}

string md5file(FILE* file) {
    MD5_CTX c;
    MD5_Init(&c);

    char buff[BUFSIZ];
    unsigned char out[16];
    size_t len = 0;
    while( ( len = fread(buff ,sizeof(char), BUFSIZ, file) ) > 0) {
        MD5_Update(&c, buff, len);
    }
    MD5_Final(out, &c);

    string res;
    for(size_t i = 0; i < 16; ++ i) {
        res.push_back(hb2hex(out[i] >> 4));
        res.push_back(hb2hex(out[i]));
    }
    return res;
}

string md5(const void* dat, size_t len) {
    string res;
    unsigned char out[16];
    md5bin(dat, len, out);
    for(size_t i = 0; i < 16; ++ i) {
        res.push_back(hb2hex(out[i] >> 4));
        res.push_back(hb2hex(out[i]));
    }
    return res;
}

std::string md5(std::string dat) {
    return md5(dat.c_str(), dat.length());
}

/* Generate shorter md5sum by something like base62 instead of base16 or base10. 0~61 are represented by 0-9a-zA-Z */
string md5sum6(const void* dat, size_t len) {
    static const char* tbl = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    string res;
    unsigned char out[16];
    md5bin(dat, len, out);
    for(size_t i = 0; i < 6; ++i) {
        res.push_back(tbl[out[i] % 62]);
    }
    return res;
}

std::string md5sum6(std::string dat) {
    return md5sum6(dat.c_str(), dat.length() );
}

}