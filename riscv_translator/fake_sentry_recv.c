#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};

    // 1. Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    // 2. Define address and port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    address.sin_port = htons(8080);       // Port 8080

    // 3. Bind
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));

    // 4. Listen
    listen(server_fd, 3); // Max 3 pending connections

    // 5. Accept and Receive
    printf("Waiting for connection...\n");
    new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
    
    //we will loop and recv from the socket aan amount equal 
    //to the size of the rotating buffer and loop reading that amount
    //and write to a file
    read(new_socket, buffer, 1024);
    printf("Received: %s\n", buffer);

    close(new_socket);
    close(server_fd);
    return 0;
}
