#ifndef TYPES_H
#define TYPES_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

typedef struct {
    int* arr;
    int count;
} int_array;

typedef struct {
    char** arr;
    int count;
} string_array;

typedef struct  {
    char* domain;
    string_array ipv4s;
    string_array ipv6s;
    bool is_blocked;
    int block_threshold; // Time in seconds to block the domain
    double current_time_on_domain; // Time in sechonds spent on the domain
    time_t last_time_packet_received;
    time_t last_time_blocked; 
} domain_info;

typedef struct {
    domain_info* arr;
    int count;
} domain_array;

typedef struct {
    uint8_t hour_to_reset; // Hour of the day to reset the blocked domains
    uint8_t minute_to_reset; // Minute of the hour to reset the blocked domains
} settings;


typedef enum {
    IPV4,
    IPV6
} IPVersion;

#endif