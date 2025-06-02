#include <stdio.h>
#include <stdlib.h>

FILE *log_file = NULL;

/* Open the log file */
void init_log(const char *filename) {
    log_file = fopen(filename, "w");  // "w" to overwrite, "a" to append
    if (!log_file) {
        perror("Failed to open log file");
        exit(1);
    }
}

/* Write a message to the log */
void write_log(const char *message) {
    if (log_file) {
        fprintf(log_file, "%s\n", message);
        fflush(log_file);  // Ensure it's written immediately
    }
}

/* Close the log file on exit */
void close_log() {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}