#ifndef AES_CODER_H_
#define AES_CODER_H_

#include <string>

namespace aes_coder {

std::string Encrypt(const std::string& plain_text);
std::string Decrypt(const std::string& cipher_text);

}

#endif  /* AES_CODER_H_ */