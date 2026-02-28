#include "../lib/receiver.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: ./%s OUTPUT_FILENAME\n", argv[0]);
        return EINVAL;
    }

    int socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socketfd < 0) {
        perror("Failed to create socket. Did you forget sudo?");
        return EPERM;
    }

    bool original_setting;
    if (set_kernel_replies(0, &original_setting) != 0) {
        fprintf(stderr, "Failed to turn off kernel echo replies. Did you forget sudo?");
        close(socketfd);
        return EPERM;
    }

    fprintf(stdout, "Listening for data...\n");
    ssize_t file_size = receive_file(socketfd, argv[1]);
    if (file_size < 0) {
        fprintf(stderr, "Error: failed to receive file (code %ld)\n", file_size);
        close(socketfd);
        return EPERM;
    }
    close(socketfd);
    fprintf(stdout, "%zd bytes of data received. Done!\n", file_size);

    bool temp;
    if (set_kernel_replies(original_setting, &temp) != 0) {
        perror("Failed to restore kernel echo replies. Did you forget sudo?");
        return EPERM;
    }
    return 0;
}
