#include "uuid.h"
#include <string.h>
#include "log/log.h"

namespace uuid {

inline uint64_t xorshift128plus(uint64_t *s) {
    uint64_t s1 = s[0];
    const uint64_t s0 = s[1];
    s[0] = s0;
    s1 ^= s1 << 23;
    s[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);
    return s[1] + s0;
}

inline UUID_STATUS init_seed(uint64_t *seed) {
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        LOG_ERROR("create uuid error, open[%s] failed.", "/dev/urandom");
        return UUID_EFAILURE;
    }
    int res = fread(seed, 1, sizeof(seed), fp);
    fclose(fp);
    if (res != sizeof(seed)) {
        return UUID_EFAILURE;
    }
    return UUID_ESUCCESS;
}

UUID_STATUS uuid4_generate(char *dst) {
    char temp_str[40] = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
    char uuid_char[20] = "0123456789abcdef";
    uint64_t seed[2];
    memset(seed, 0, 2 * sizeof(uint64_t));
    do {
        UUID_STATUS err = init_seed(seed);
        if (err != UUID_ESUCCESS) {
            LOG_ERROR("create uuid error, init seed failed.");
            return err;
        }
    } while (seed[0] == 0 && seed[1] == 0);
    union { unsigned char b[16]; uint64_t word[2]; } s;
    s.word[0] = xorshift128plus(seed);
    s.word[1] = xorshift128plus(seed);
    char *p = temp_str;
    int i = 0;
    while (*p) {
        int n = s.b[i >> 1];
        n = (i & 1) ? (n >> 4) : (n & 0xf);
        switch (*p) {
            case 'x' :
                *dst = uuid_char[n];
                i++;
                break;
            case 'y' :
                *dst = uuid_char[(n & 0x3) + 8];
                i++;
                break;
            default :
                *dst = *p;
        }
        dst++, p++;
    }
    *dst = '\0';
    return UUID_ESUCCESS;
}

UUID_STATUS uuid4_generate(std::string &dst) {
    char uuid[UUID_LEN] = {0};
    UUID_STATUS rtn = uuid4_generate(uuid);
    if (UUID_EFAILURE != rtn) {
        dst = std::string(uuid);
    }
    return rtn;
}

}
