#include "aes_coder.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "openssl/aes.h"
#include "openssl/evp.h"
#include "log/log.h"

namespace aes_coder {

static const unsigned char MY_AES_KEY[] = {
    0x3b, 0x19, 0x6d, 0x45, 0xaf, 0x27, 0x34, 0xd1, 0xbd, 0x3c, 0xa3,
    0x57, 0x71, 0x45, 0x69, 0x9d, 0x92, 0x04, 0x74, 0x52, 0x97, 0x4c,
    0x88, 0x77, 0xfb, 0xdd, 0x33, 0x72, 0x44, 0x57, 0x97, 0x65};

static bool CharToHex(const char high_c, const char low_c,
                      unsigned char *buff) {
    unsigned char high, low;
    if (high_c >= '0' && high_c <= '9')
        high = high_c - '0';
    else if (high_c >= 'A' && high_c <= 'F')
        high = high_c - 'A' + 10;
    else if (high_c >= 'a' && high_c <= 'f')
        high = high_c - 'a' + 10;
    else
        return false;

    if (low_c >= '0' && low_c <= '9')
        low = low_c - '0';
    else if (low_c >= 'A' && low_c <= 'F')
        low = low_c - 'A' + 10;
    else if (low_c >= 'a' && low_c <= 'f')
        low = low_c - 'a' + 10;
    else
        return false;

    *buff = high << 4 | low;
    return true;
}

static std::string ByteToStr(const unsigned char *buffer, size_t len) {
    char char_buf[3] = {0};
    std::string ret;
    size_t converted_len = 0;
    while (converted_len < len) {
        snprintf(char_buf, sizeof(char_buf), "%02X", *(buffer + converted_len));
        ret += reinterpret_cast<const char *>(char_buf);
        ++converted_len;
    }
    return ret;
}

static unsigned char *GetStrToByte(const std::string &str, size_t &len) {
    if (str.size() % 2 != 0) {
        LOG_ERROR("wrong len when decode");
        return NULL;
    }
    unsigned char *buff = new (std::nothrow) unsigned char[str.size() / 2];
    if (buff == NULL) {
        LOG_ERROR("out of memory when decode");
        return buff;
    }
    bool ok = true;
    size_t write_str_len = 0;
    len = 0;
    while (write_str_len < str.size()) {
        if (!CharToHex(str[write_str_len], str[write_str_len + 1],
                       buff + len)) {
            ok = false;
            break;
        }
        write_str_len += 2;
        ++len;
    }
    if (ok) {
        return buff;
    }
    delete[] buff;
    return NULL;
}

static void PutStrToByte(unsigned char *buff) { delete[] buff; }

std::string Encrypt(const std::string &plain_text) {
    EVP_CIPHER_CTX cipher_ctx;
    EVP_CIPHER_CTX_init(&cipher_ctx);

    std::string encrypted_str;
    unsigned char *cipher_buffer = NULL;
    do {
        unsigned char iv[EVP_MAX_IV_LENGTH] = {0};
        srand((unsigned)time(NULL));
        for (int i = 0; i < EVP_MAX_IV_LENGTH; i++) {
            iv[i] = rand() % 255;
        }

        const EVP_CIPHER *cipher_type = EVP_aes_256_cbc();
        if (EVP_EncryptInit(&cipher_ctx, cipher_type, MY_AES_KEY, iv) == 0) {
            LOG_ERROR("init encode failed");
            break;
        }

        int bytes_written = 0;
        int cipher_text_len = 0;
        int cipher_block_size = EVP_CIPHER_block_size(cipher_type);
        cipher_buffer = new (
            std::nothrow) unsigned char[plain_text.size() + cipher_block_size];
        if (cipher_buffer == NULL) {
            LOG_ERROR("out of memory when encode");
            break;
        }

        if (EVP_EncryptUpdate(
                &cipher_ctx, cipher_buffer, &bytes_written,
                reinterpret_cast<const unsigned char *>(plain_text.c_str()),
                plain_text.size()) == 0) {
            LOG_ERROR("encode failed");
            break;
        }
        cipher_text_len += bytes_written;
        if (EVP_EncryptFinal(&cipher_ctx, cipher_buffer + cipher_text_len,
                             &bytes_written) == 0) {
            LOG_ERROR("finish encode failed");
            break;
        }
        cipher_text_len += bytes_written;

        encrypted_str += ByteToStr(iv, EVP_CIPHER_iv_length(cipher_type));
        encrypted_str += ByteToStr(cipher_buffer, cipher_text_len);
    } while (false);
    if (cipher_buffer) {
        delete[] cipher_buffer;
    }
    EVP_CIPHER_CTX_cleanup(&cipher_ctx);
    return encrypted_str;
}

std::string Decrypt(const std::string &cipher_text) {
    size_t buff_len = 0;
    const EVP_CIPHER *cipher_type = EVP_aes_256_cbc();
    int iv_len = EVP_CIPHER_iv_length(cipher_type);
    if (cipher_text.size() <= static_cast<size_t>(iv_len)) {
        return std::string();
    }

    unsigned char *buff = GetStrToByte(cipher_text, buff_len);
    if (buff == NULL) {
        return std::string();
    }

    EVP_CIPHER_CTX cipher_ctx;
    EVP_CIPHER_CTX_init(&cipher_ctx);

    std::string decrypted_str;
    unsigned char *plain_buffer = NULL;
    do {
        unsigned char *iv = buff;
        if (EVP_DecryptInit(&cipher_ctx, cipher_type, MY_AES_KEY, iv) == 0) {
            LOG_ERROR("init decode failed");
            break;
        }
        int plain_block_size = EVP_CIPHER_block_size(cipher_type);
        plain_buffer = new (
            std::nothrow) unsigned char[cipher_text.size() + plain_block_size];
        if (plain_buffer == NULL) {
            LOG_ERROR("out of memory when decode");
            break;
        }

        int bytes_written = 0;
        int plain_text_len = 0;
        if (EVP_DecryptUpdate(&cipher_ctx, plain_buffer + plain_text_len,
                              &bytes_written, buff + iv_len,
                              buff_len - iv_len) == 0) {
            // Do not log this in release version, because the decode fail info may be useed to do pedding attack
            LOG_DEBUG("decode failed");
            break;
        }
        plain_text_len += bytes_written;
        if (EVP_DecryptFinal(&cipher_ctx, plain_buffer + plain_text_len,
                             &bytes_written) == 0) {
            // Do not log this in release version, because the decode fail info
            // may be useed to do pedding attack
            LOG_DEBUG("finish decode failed");
            break;
        }
        plain_text_len += bytes_written;
        decrypted_str = std::string(
            reinterpret_cast<const char *>(plain_buffer), plain_text_len);
    } while (false);
    if (plain_buffer) {
        delete[] plain_buffer;
    }
    if (buff) {
        PutStrToByte(buff);
    }
    EVP_CIPHER_CTX_cleanup(&cipher_ctx);
    return decrypted_str;
}

}
