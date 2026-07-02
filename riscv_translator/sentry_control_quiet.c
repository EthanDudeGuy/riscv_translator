#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
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
            return -1;
        }
        if (n == 0) return -1;
        p += n;
        len -= n;
    }

    return 1;
}

static int discard_bytes(int fd, uint64_t len) {
    uint8_t buf[65536];

    while (len > 0) {
        size_t chunk = len > sizeof(buf) ? sizeof(buf) : (size_t)len;
        int rc = recv_all(fd, buf, chunk);
        if (rc <= 0) return rc;
        len -= chunk;
    }

    return 1;
}

static int connect_proxy(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(9091);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        return -1;
    }

    return fd;
}

int main(void) {
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) return 1;
    uint64_t vals_received = 0;

    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(9090);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) return 1;
    if (listen(listenfd, 1) < 0) return 1;

    int clientfd = accept(listenfd, NULL, NULL);
    if (clientfd < 0) return 1;

    int proxyfd = connect_proxy();

    while (1) {
        scPacketHeader header;

        int rc = recv_all(clientfd, &header, sizeof(header));
        if (rc <= 0) break;

        if (header.type == PKT_TRACE) {
	    vals_received += header.count;
            rc = discard_bytes(clientfd, header.count * sizeof(uint64_t));
            if (rc <= 0) break;
        } else if (header.type == PKT_SEND) {
            if (proxyfd < 0) break;

            send_all(proxyfd, &header, sizeof(header));

            uint8_t buf[65536];
            uint64_t remaining = header.count;

            while (remaining > 0) {
                size_t chunk = remaining > sizeof(buf) ? sizeof(buf) : (size_t)remaining;
                rc = recv_all(clientfd, buf, chunk);
                if (rc <= 0) goto done;
                if (send_all(proxyfd, buf, chunk) <= 0) goto done;
                remaining -= chunk;
            }
        } else if (header.type == PKT_RECV) {
            if (proxyfd < 0) break;

            if (send_all(proxyfd, &header, sizeof(header)) <= 0) break;

            uint64_t actual_len = 0;
            rc = recv_all(proxyfd, &actual_len, sizeof(actual_len));
            if (rc <= 0) break;

            if (send_all(clientfd, &actual_len, sizeof(actual_len)) <= 0) break;

            uint8_t buf[65536];
            uint64_t remaining = actual_len;

            while (remaining > 0) {
                size_t chunk = remaining > sizeof(buf) ? sizeof(buf) : (size_t)remaining;
                rc = recv_all(proxyfd, buf, chunk);
                if (rc <= 0) goto done;
                if (send_all(clientfd, buf, chunk) <= 0) goto done;
                remaining -= chunk;
            }
        } else {
            break;
        }
    }

done:
    printf("vals received total = %ld\n", vals_received);
    close(proxyfd);
    close(clientfd);
    close(listenfd);

    return 0;
}
