#ifndef ENCRYPTORX_HPP
#define ENCRYPTORX_HPP

#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>

namespace encryptorx {

class EncryptorException : public std::runtime_error {
public:
    explicit EncryptorException(const std::string& msg) : std::runtime_error(msg) {}
};

class EncryptorX {
public:
    static constexpr const char* VERSION = "3.0.0";

    // Cifrar texto usando el algoritmo Null-Obfuscated Cipher
    static std::string encrypt(
        const std::string& plaintext,
        const std::string& password = "",
        char delimiter = '$'
    );

    // Descifrar token cifrado
    static std::string decrypt(
        const std::string& token,
        const std::string& password = ""
    );

    // Cifrado y descifrado de archivos
    static void encryptFile(
        const std::string& sourcePath,
        const std::string& destPath = "",
        const std::string& password = ""
    );

    static void decryptFile(
        const std::string& sourcePath,
        const std::string& destPath = "",
        const std::string& password = ""
    );
};

} // namespace encryptorx

#endif // ENCRYPTORX_HPP
