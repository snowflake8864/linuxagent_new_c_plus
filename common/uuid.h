#ifndef UUID_H_
#define UUID_H_

#include <stdint.h>
#include <stdio.h>
#include <string>

#define UUID_LEN 37

namespace uuid {

enum UUID_STATUS{
    UUID_ESUCCESS =  0,
    UUID_EFAILURE = -1
};

UUID_STATUS uuid4_generate(char *dst);
UUID_STATUS uuid4_generate(std::string &dst);

} // namespace

#endif /* UUID_H_*/