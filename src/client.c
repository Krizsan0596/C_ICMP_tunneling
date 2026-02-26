#include "../lib/receiver.h"
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: ./%s OUTPUT_FILENAME", argv[0]);
        return 1;
    }

    int socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socketfd < 0) {
        perror("socket");
        return 1;
    }

    int ret = receive_file(socketfd, argv[1]);
    if (ret != 0) {
        fprintf(stderr, "Error: failed to receive file (code %d)\n", ret);
        close(socketfd);
        return 1;
    }
    close(socketfd);
    return 0;
}
