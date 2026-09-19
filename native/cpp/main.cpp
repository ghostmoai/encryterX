#include "encryptorx.hpp"
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "EncryptorX C++ CLI v" << encryptorx::EncryptorX::VERSION << "\n";
        std::cout << "Uso:\n";
        std::cout << "  " << argv[0] << " -e \"mensaje\" [password] [separador]\n";
        std::cout << "  " << argv[0] << " -d \"token\" [password]\n";
        std::cout << "  " << argv[0] << " --test\n";
        return 0;
    }

    std::string cmd = argv[1];

    if (cmd == "--test") {
        std::string msg = "Prueba nativa de EncryptorX en C++17!";
        std::cout << "[TEST C++] Cifrando: '" << msg << "'\n";
        try {
            std::string token = encryptorx::EncryptorX::encrypt(msg, "", '$');
            std::cout << "[TEST C++] Token (len " << token.length() << ")\n";
            std::string dec = encryptorx::EncryptorX::decrypt(token);
            std::cout << "[TEST C++] Descifrado: '" << dec << "'\n";
            if (dec == msg) {
                std::cout << "[TEST C++] C++ NATIVE TEST PASSED 100%!\n";
                return 0;
            } else {
                std::cerr << "[TEST C++] ERROR: Mismatch!\n";
                return 1;
            }
        } catch (const std::exception& e) {
            std::cerr << "[TEST C++] ERROR: " << e.what() << "\n";
            return 1;
        }
    }

    if (cmd == "-e" && argc >= 3) {
        std::string text = argv[2];
        std::string pwd = (argc >= 4) ? argv[3] : "";
        char sep = (argc >= 5) ? argv[4][0] : '$';
        try {
            std::cout << encryptorx::EncryptorX::encrypt(text, pwd, sep) << "\n";
            return 0;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << "\n";
            return 1;
        }
    }

    if (cmd == "-d" && argc >= 3) {
        std::string token = argv[2];
        std::string pwd = (argc >= 4) ? argv[3] : "";
        try {
            std::cout << encryptorx::EncryptorX::decrypt(token, pwd) << "\n";
            return 0;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << "\n";
            return 1;
        }
    }

    std::cerr << "Comando no reconocido.\n";
    return 1;
}
