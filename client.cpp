#include <iostream>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

const char* SERVER_IP = "127.0.0.1";
const int PORT = 12345;
const int BUFFER_SIZE = 1024;

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void communicate_with_server(SOCKET client_socket, SSL_CTX* ssl_ctx) {
    char buffer[BUFFER_SIZE] = {0};

    // Send username and password
    std::string username = "user";
    std::string password = "password";
    std::string credentials = username + ":" + password;
    send(client_socket, credentials.c_str(), credentials.size(), 0);

    // Receive authentication response
    recv(client_socket, buffer, BUFFER_SIZE, 0);
    std::cout << buffer << std::endl;

    if (std::string(buffer) == "Authentication failed") {
        closesocket(client_socket);
        return;
    }

    // Communication loop
    while (true) {
        std::cout << "You: ";
        std::string message;
        std::getline(std::cin, message);

        // Encrypt message
        unsigned char encrypted[BUFFER_SIZE];
        int encrypted_len = encrypt((unsigned char*)message.c_str(), message.length(), ssl_ctx, encrypted);
        send(client_socket, (char*)encrypted, encrypted_len, 0);

        // Receive encrypted response
        memset(buffer, 0, BUFFER_SIZE);
        int len = recv(client_socket, buffer, BUFFER_SIZE, 0);

        // Decrypt response
        unsigned char decrypted[BUFFER_SIZE];
        int decrypted_len = decrypt((unsigned char*)buffer, len, ssl_ctx, decrypted);
        decrypted[decrypted_len] = '\0';
        std::cout << "Server: " << decrypted << std::endl;
    }

    closesocket(client_socket);
}

int main() {
    // Initialize Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Create client socket
    SOCKET client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed" << std::endl;
        WSACleanup();
        return 1;
    }

    // Connect to server
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(PORT);
    if (connect(client_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "Connection failed" << std::endl;
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }

    // Initialize OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        std::cerr << "SSL context creation failed" << std::endl;
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }

    // Setup the SSL connection
    SSL* ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, client_socket);
    if (SSL_connect(ssl) != 1) {
        std::cerr << "SSL connection failed" << std::endl;
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }

    // Communicate with the server
    communicate_with_server(client_socket, ssl);

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    closesocket(client_socket);
    WSACleanup();
    return 0;
}
