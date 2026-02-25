#include "../lib/receiver.h"
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: ./%s OUTPUT_FILENAME", argv[0]);
        return 1;
    }

    int socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    receive_file(socketfd, argv[1]);
    close(socketfd);
    return 0;
}
