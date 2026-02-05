sliding_window window = {
    .queue = {0},
    .count = 0,
    .head = 0,
    .tail = 0,
    .next_sequence = 1
};
pthread_mutex_init(&window.lock, NULL);
sem_init(&window.counter, 0, 5);
