#include <iostream>
#include <string>
#include <thread>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

const int PORT = 12345;
const int BUFFER_SIZE = 1024;
const int KEY_LENGTH = 32;
const int IV_LENGTH = 16;

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void generate_key_iv(unsigned char* key, unsigned char* iv) {
    RAND_bytes(key, KEY_LENGTH);
    RAND_bytes(iv, IV_LENGTH);
}

void communicate_with_client(SOCKET client_socket, unsigned char* key, unsigned char* iv) {
    char buffer[BUFFER_SIZE] = {0};

    // Receive username and password
    recv(client_socket, buffer, BUFFER_SIZE, 0);
    std::string credentials(buffer);

    size_t pos = credentials.find(":");
    std::string username = credentials.substr(0, pos);
    std::string password = credentials.substr(pos + 1);

    // Simple authentication
    if (username == "user" && password == "password") {
        std::string response = "Authentication successful";
        send(client_socket, response.c_str(), response.size(), 0);
    } else {
        std::string response = "Authentication failed";
        send(client_socket, response.c_str(), response.size(), 0);
        closesocket(client_socket);
        return;
    }

    // Communication loop
    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        int len = recv(client_socket, buffer, BUFFER_SIZE, 0);
        if (len <= 0) break;

        // Decrypt message
        unsigned char decrypted[BUFFER_SIZE];
        int decrypted_len = decrypt((unsigned char*)buffer, len, key, iv, decrypted);
        decrypted[decrypted_len] = '\0';
        std::cout << "Client: " << decrypted << std::endl;

        // Encrypt response
        std::string reply = "Message received";
        unsigned char encrypted[BUFFER_SIZE];
        int encrypted_len = encrypt((unsigned char*)reply.c_str(), reply.length(), key, iv, encrypted);
        send(client_socket, (char*)encrypted, encrypted_len, 0);
    }

    closesocket(client_socket);
}

int main() {
    // Initialize Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Create server socket
    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed" << std::endl;
        return 1;
    }

    // Bind server socket
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    if (bind(server_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "Socket bind failed" << std::endl;
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    // Listen for incoming connections
    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed" << std::endl;
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server listening on port " << PORT << std::endl;

    // Generate key and IV for encryption
    unsigned char key[KEY_LENGTH], iv[IV_LENGTH];
    generate_key_iv(key, iv);

    // Accept and handle client connections
    while (true) {
        SOCKET client_socket = accept(server_socket, NULL, NULL);
        if (client_socket == INVALID_SOCKET) {
            std::cerr << "Accept failed" << std::endl;
            closesocket(server_socket);
            WSACleanup();
            return 1;
        }

        // Handle communication with client in a separate thread
        std::thread(communicate_with_client, client_socket, key, iv).detach();
    }

    // Cleanup
    closesocket(server_socket);
    WSACleanup();
    return 0;
}
