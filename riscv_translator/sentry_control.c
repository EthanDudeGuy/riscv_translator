#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PKT_TRACE 1
#define PKT_SEND_VALUE 2
#define PKT_RECV_VALUE 3

typedef struct {
    uint64_t type;
    uint64_t count;
} SentryPacketHeader;

static int recv_all(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;

    while (len > 0) {
        ssize_t n = recv(fd, p, len, 0);

        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recv");
            return -1;
        }

        if (n == 0) return 0;

        p += n;
        len -= n;
    }

    return 1;
}

static const char *packet_type_name(uint64_t type) {
    if (type == PKT_TRACE) return "TRACE";
    if (type == PKT_SEND_VALUE) return "SEND_VALUE";
    if (type == PKT_RECV_VALUE) return "RECV_VALUE";
    return "UNKNOWN";
}

int main(void) {
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);

    if (listenfd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(9090);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(listenfd, 1) < 0) {
        perror("listen");
        return 1;
    }

    printf("Waiting for connection on 127.0.0.1:9090...\n");

    int clientfd = accept(listenfd, NULL, NULL);

    if (clientfd < 0) {
        perror("accept");
        return 1;
    }

    printf("Client connected\n");

    while (1) {
        SentryPacketHeader header;

        int rc = recv_all(clientfd, &header, sizeof(header));

        if (rc <= 0) break;

        printf("\n=== Packet ===\n");
        printf("Type:  %lu (%s)\n", header.type, packet_type_name(header.type));
        printf("Count: %lu\n", header.count);

        for (uint64_t i = 0; i < header.count; i++) {
            uint64_t value;

            rc = recv_all(clientfd, &value, sizeof(value));

            if (rc <= 0) goto done;

            printf("[%5lu] 0x%016lx (%lu)\n", i, value, value);
        }

        if (header.type == PKT_RECV_VALUE) {
            uint64_t response = 12345;
            send(clientfd, &response, sizeof(response), 0);
            printf("Sent response: 0x%016lx (%lu)\n", response, response);
        }
    }

done:
    printf("\nConnection closed\n");

    close(clientfd);
    close(listenfd);

    return 0;
}
