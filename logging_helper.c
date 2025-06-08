#include <stdio.h>
#include <stdlib.h>
#include "logging_helper.h"

static FILE *log_file = NULL;  // Only visible inside this file

void init_log(const char *filename) {
    log_file = fopen(filename, "w");  // or "a" for append
    if (!log_file) {
        perror("Failed to open log file");
        exit(1);
    }
}

void write_log(const char *message) {
    if (log_file) {
        fprintf(log_file, "%s\n", message);
        fflush(log_file);
    }
}

void close_log(void) {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}
