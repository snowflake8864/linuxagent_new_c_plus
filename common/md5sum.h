
#ifndef MD5SUM_H_
#define MD5SUM_H_

#include <stdio.h>
#include <string>
#include <cstring>

namespace md5sum {

std::string md5(std::string dat);
std::string md5(const void* dat, size_t len);
std::string md5file(const char* filename);
std::string md5file(FILE* file);
std::string md5sum6(std::string dat);
std::string md5sum6(const void* dat, size_t len);

}

#endif /* MD5SUM_H_ */