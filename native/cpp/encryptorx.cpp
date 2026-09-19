#include "encryptorx.hpp"
#include "../c/encryptorx.h"
#include <fstream>
#include <sstream>
#include <cstdlib>

namespace encryptorx {

std::string EncryptorX::encrypt(
    const std::string& plaintext,
    const std::string& password,
    char delimiter
) {
    if (plaintext.empty()) return "";
    const char* pwd_cstr = password.empty() ? nullptr : password.c_str();
    char* token = encryptorx_encrypt(plaintext.c_str(), pwd_cstr, delimiter);
    if (!token) {
        throw EncryptorException("Error al cifrar el texto.");
    }
    std::string result(token);
    std::free(token);
    return result;
}

std::string EncryptorX::decrypt(
    const std::string& token,
    const std::string& password
) {
    if (token.empty()) return "";
    const char* pwd_cstr = password.empty() ? nullptr : password.c_str();
    char error_buf[256] = {0};
    char* plaintext = encryptorx_decrypt(token.c_str(), pwd_cstr, error_buf, sizeof(error_buf));
    if (!plaintext) {
        throw EncryptorException(std::string("Fallo al descifrar: ") + error_buf);
    }
    std::string result(plaintext);
    std::free(plaintext);
    return result;
}

} // namespace encryptorx
