
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "../lib/sender.h"

extern volatile _Atomic program_state state;

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
    
    pthread_create(&producer_thread, NULL, start_thread, producer_args);
    ssize_t *file_size;

    sig.sa_handler = &handle_sigint;
    sig.sa_flags = 0;
    sigemptyset(&sig.sa_mask);
    sigaction(SIGINT, &sig, NULL);

    pthread_sigmask(SIG_UNBLOCK, &set, NULL);

    while (state != ABORT && state != FINISHED) {
        pthread_join(producer_thread, (void **)&file_size);
    }

    return 0;
}
