
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include "../lib/sender.h"

volatile _Atomic program_state state = RUNNING;

void handle_sigint(int sig){
    state = ABORT;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: ./%s INPUT_FILENAME DESTINATION_IP\n", argv[0]);
        return EXIT_FAILURE;
    }

    sigset_t set;
    struct sigaction sig;

    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    pthread_t producer_thread;
    thread_args *producer_args = malloc(sizeof(thread_args));
    producer_args->file = argv[1];
    producer_args->dest_ip = argv[2];
    producer_args->task = WRAPPER;
    
    fprintf(stdout, "Preparing to send data...\n");
    if (pthread_create(&producer_thread, NULL, start_thread, producer_args) != 0) return EAGAIN;
    ssize_t *file_size;

    sig.sa_handler = &handle_sigint;
    sig.sa_flags = 0;
    sigemptyset(&sig.sa_mask);
    sigaction(SIGINT, &sig, NULL);

    pthread_sigmask(SIG_UNBLOCK, &set, NULL);

    pthread_join(producer_thread, (void **)&file_size);

    if (file_size == NULL || *file_size < 0) {
        fprintf(stderr, "Error: failed to send data.\n");
    } else {
        fprintf(stdout, "%zd bytes of data sent. Done!\n", *file_size);
    }
    free(file_size);
    free(producer_args);

    return 0;
}
