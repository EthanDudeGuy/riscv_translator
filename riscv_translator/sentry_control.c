#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PKT_TRACE 1
#define PKT_SEND  2
#define PKT_RECV  3

typedef struct {
    uint64_t type;
    uint64_t count;
} scPacketHeader;

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

static int send_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;

    while (len > 0) {
        ssize_t n = send(fd, p, len, 0);

        if (n < 0) {
            if (errno == EINTR) continue;
            perror("send");
            return -1;
        }

        if (n == 0) return -1;

        p += n;
        len -= n;
    }

    return 1;
}

static const char *packet_type_name(uint64_t type) {
    if (type == PKT_TRACE) return "TRACE";
    if (type == PKT_SEND)  return "SEND";
    if (type == PKT_RECV)  return "RECV";
    return "UNKNOWN";
}

static void print_payload(uint8_t *buf, uint64_t len) {
    printf("Payload bytes: ");

    for (uint64_t i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
    }

    printf("\nPayload text:  ");

    for (uint64_t i = 0; i < len; i++) {
        if (isprint(buf[i])) {
            putchar(buf[i]);
        } else if (buf[i] == 0) {
            printf("\\0");
        } else {
            putchar('.');
        }
    }

    printf("\n");
}

static int connect_proxy(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        perror("proxy socket");
        exit(1);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(9091);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect proxy");
        exit(1);
    }

    return fd;
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
        perror("bind sentry_control");
        return 1;
    }

    if (listen(listenfd, 1) < 0) {
        perror("listen sentry_control");
        return 1;
    }

    printf("Waiting for translated program on 127.0.0.1:9090...\n");

    int clientfd = accept(listenfd, NULL, NULL);

    if (clientfd < 0) {
        perror("accept");
        return 1;
    }

    printf("Translated program connected\n");

    int proxyfd = connect_proxy();

    printf("Network proxy connected on 127.0.0.1:9091\n");

    while (1) {
        scPacketHeader header;

        int rc = recv_all(clientfd, &header, sizeof(header));

        if (rc <= 0) break;

        printf("\n=== Packet ===\n");
        printf("Type:  %lu (%s)\n", header.type, packet_type_name(header.type));
        printf("Count: %lu\n", header.count);

        if (header.type == PKT_TRACE) {
            for (uint64_t i = 0; i < header.count; i++) {
                uint64_t value;

                rc = recv_all(clientfd, &value, sizeof(value));

                if (rc <= 0) goto done;

                printf("[%5lu] 0x%016lx (%lu)\n", i, value, value);
            }
        } else if (header.type == PKT_SEND) {
            uint8_t *buf = malloc(header.count);

            if (!buf) {
                perror("malloc");
                goto done;
            }

            rc = recv_all(clientfd, buf, header.count);

            if (rc <= 0) {
                free(buf);
                goto done;
            }

            print_payload(buf, header.count);

            send_all(proxyfd, &header, sizeof(header));
            send_all(proxyfd, buf, header.count);

            free(buf);
        } else if (header.type == PKT_RECV) {
            printf("Forwarding RECV request for max %lu bytes\n", header.count);

            send_all(proxyfd, &header, sizeof(header));

            uint64_t actual_len = 0;

            rc = recv_all(proxyfd, &actual_len, sizeof(actual_len));

            if (rc <= 0) goto done;

            uint8_t *buf = malloc(actual_len);

            if (!buf) {
                perror("malloc");
                goto done;
            }

            rc = recv_all(proxyfd, buf, actual_len);

            if (rc <= 0) {
                free(buf);
                goto done;
            }

            printf("Proxy returned %lu bytes\n", actual_len);
            print_payload(buf, actual_len);

            send_all(clientfd, &actual_len, sizeof(actual_len));
            send_all(clientfd, buf, actual_len);

            free(buf);
        } else {
            printf("Unknown packet type. Stopping to avoid stream desync.\n");
            break;
        }
    }

done:
    printf("\nConnection closed\n");

    close(proxyfd);
    close(clientfd);
    close(listenfd);

    return 0;
}
