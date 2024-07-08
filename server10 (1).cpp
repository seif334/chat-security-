#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fstream>

const int PORT = 12345;
const int BUFFER_SIZE = 1024;
const char *ENCRYPTION_KEY = "mysecretkey"; // Encryption key (should be kept secret)

// Function to decrypt message using XOR with a key
void decryptMessage(char *message, size_t len, const char *key) {
    size_t keyLen = strlen(key);
    for (size_t i = 0; i < len; ++i) {
        message[i] ^= key[i % keyLen];
    }
}

int main() {
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);

    // Create socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return 1;
    }

    // Set SO_REUSEADDR option to allow address reuse
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        std::cerr << "Error setting socket options" << std::endl;
        return 1;
    }

    // Bind socket to IP and port
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Error binding socket" << std::endl;
        return 1;
    }

    // Listen for incoming connections
    if (listen(serverSocket, 5) < 0) {
        std::cerr << "Error listening for connections" << std::endl;
        return 1;
    }

    std::cout << "Server listening on port " << PORT << std::endl;

    // Accept incoming connections
    while (true) {
        clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &clientAddrLen);
        if (clientSocket < 0) {
            std::cerr << "Error accepting connection" << std::endl;
            continue;
        }

        std::cout << "New connection accepted" << std::endl;

        // Open file for storing encrypted messages
        std::ofstream outFile("messages.txt", std::ios::app | std::ios::binary);
        if (!outFile.is_open()) {
            std::cerr << "Error opening file for writing" << std::endl;
            close(clientSocket);
            continue;
        }

        // Chat loop
        char buffer[BUFFER_SIZE];
        int bytesRead;
        while (true) {
            // Receive message from client
            memset(buffer, 0, BUFFER_SIZE);
            bytesRead = recv(clientSocket, buffer, BUFFER_SIZE, 0);
            if (bytesRead <= 0) {
                std::cout << "Client disconnected" << std::endl;
                break;
            }

            // Store encrypted message in file
            outFile.write(buffer, bytesRead);
            outFile.write("\n", 1);

            // Print message to server terminal
            std::cout << "Client: " << buffer << std::endl;
        }

        outFile.close();
        close(clientSocket);
    }

    close(serverSocket);
    return 0;
}
