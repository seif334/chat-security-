#include <iostream>
#include <cstring>
#include <fstream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

const int PORT = 12345;
const int BUFFER_SIZE = 1024;
const char* MESSAGE_FILE = "messages.txt";

// Simple XOR encryption function
void encryptMessage(char* message) {
    char key = 'K'; // Encryption key
    size_t len = strlen(message);
    for (size_t i = 0; i < len; ++i) {
        message[i] ^= key;
    }
}

void logEncryptedMessage(const char* encryptedMessage) {
    std::ofstream file(MESSAGE_FILE, std::ios::app);
    if (file.is_open()) {
        file << encryptedMessage << std::endl;
        file.close();
    } else {
        std::cerr << "Error opening file for writing" << std::endl;
    }
}

bool authenticateUser(const std::string& username, const std::string& password) {
    return (username == "seif" && password == "1234");
}

int main() {
    int clientSocket;
    struct sockaddr_in serverAddr;

    // Prompt user for username and password
    std::string username, password;
    std::cout << "Enter username: ";
    std::cin >> username;
    std::cout << "Enter password: ";
    std::cin >> password;

    // Check authentication
    if (!authenticateUser(username, password)) {
        std::cerr << "Authentication failed. Closing connection." << std::endl;
        return 1;
    }

    // Create socket
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return 1;
    }

    // Connect to server
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Error connecting to server" << std::endl;
        return 1;
    }

    std::cout << "Connected to server" << std::endl;

    // Chat loop
    char buffer[BUFFER_SIZE];
    while (true) {
        // Prompt user for message
        std::cout << "Enter message to send (type 'exit' to quit): ";
        std::cin.ignore();  // Clear input buffer
        std::cin.getline(buffer, BUFFER_SIZE);

        // Check if user wants to exit
        if (strcmp(buffer, "exit") == 0) {
            break;
        }

        // Encrypt message
        encryptMessage(buffer);

        // Send encrypted message to server
        send(clientSocket, buffer, strlen(buffer), 0);
        std::cout << "Message sent: " << buffer << std::endl;

        // Log encrypted message to file
        logEncryptedMessage(buffer);
    }

    close(clientSocket);

    return 0;
}
