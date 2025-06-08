#ifndef LOG_HELPER_H
#define LOG_HELPER_H

#include <stdio.h>

/* Initializes the log file */
void init_log(const char *filename);

/* Writes a message to the log */
void write_log(const char *message);

/* Closes the log file */
void close_log(void);

#endif
