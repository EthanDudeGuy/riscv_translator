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

#define PROXY_PORT 9091
#define REAL_SERVER_IP "127.0.0.1"
#define REAL_SERVER_PORT 8080

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

        p += n;
        len -= n;
    }

    return 1;
}

static int connect_real_server(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        perror("real socket");
        exit(1);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "bad real server ip\n");
        exit(1);
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect real server");
        exit(1);
    }

    return fd;
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

int main(void) {
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);

    if (listenfd < 0) {
        perror("proxy socket");
        return 1;
    }

    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));

    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(PROXY_PORT);
    proxy_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(listenfd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) {
        perror("bind proxy");
        return 1;
    }

    if (listen(listenfd, 1) < 0) {
        perror("listen proxy");
        return 1;
    }

    printf("network_proxy listening on 127.0.0.1:%d\n", PROXY_PORT);

    int scfd = accept(listenfd, NULL, NULL);

    if (scfd < 0) {
        perror("accept sentry_control");
        return 1;
    }

    printf("sentry_control connected\n");

    int realfd = connect_real_server(REAL_SERVER_IP, REAL_SERVER_PORT);

    printf("connected to real server %s:%d\n",
           REAL_SERVER_IP,
           REAL_SERVER_PORT);

    while (1) {
        scPacketHeader h;

        int rc = recv_all(scfd, &h, sizeof(h));

        if (rc <= 0) break;

        if (h.type == PKT_SEND) {
            uint8_t *buf = malloc(h.count);

            if (!buf) {
                perror("malloc");
                break;
            }

            rc = recv_all(scfd, buf, h.count);

            if (rc <= 0) {
                free(buf);
                break;
            }

            printf("\nPROXY SEND %lu bytes\n", h.count);
            print_payload(buf, h.count);

            if (send_all(realfd, buf, h.count) <= 0) {
                free(buf);
                break;
            }

            free(buf);
        } else if (h.type == PKT_RECV) {
            uint8_t *buf = malloc(h.count);

            if (!buf) {
                perror("malloc");
                break;
            }

            printf("\nPROXY RECV request max=%lu\n", h.count);

            ssize_t n = recv(realfd, buf, h.count, 0);

            if (n < 0) {
                if (errno == EINTR) {
                    free(buf);
                    continue;
                }

                perror("recv real server");
                free(buf);
                break;
            }

            if (n == 0) {
                printf("real server closed connection\n");
                free(buf);
                break;
            }

            uint64_t actual_len = (uint64_t)n;

            printf("PROXY RECV got %lu bytes\n", actual_len);
            print_payload(buf, actual_len);

            send_all(scfd, &actual_len, sizeof(actual_len));
            send_all(scfd, buf, actual_len);

            free(buf);
        } else {
            printf("network_proxy got unknown packet type %lu\n", h.type);
            break;
        }
    }

    printf("network_proxy shutting down\n");

    close(realfd);
    close(scfd);
    close(listenfd);

    return 0;
}
