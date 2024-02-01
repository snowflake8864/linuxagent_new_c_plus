
#ifndef _SM3_H_
#define _SM3_H_

#include <inttypes.h>
#include <string>
#include <stdio.h>

#define SM3_DIGEST_SIZE 32

namespace sm3sum {

int sm3(const void *input_data, int data_len, unsigned char output[SM3_DIGEST_SIZE]);
std::string sm3(const void *input_data, int data_len);

int sm3file(FILE *file, unsigned char output[SM3_DIGEST_SIZE]);
std::string sm3file(FILE *file);

int sm3sum(const char *file_path, unsigned char output[SM3_DIGEST_SIZE]);
std::string sm3sum(const char *file_path);

}

#endif

