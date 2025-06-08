#ifndef TYPES_H
#define TYPES_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define DOMAINS_FILE_UPDATE "domains_file_update"

typedef struct {
    int* arr;
    int count;
} IntArray;

typedef struct {
    char** arr;
    int count;
} StringArray;

typedef struct  {
    char* domain;
    StringArray ipv4s;
    StringArray ipv6s;
    bool is_blocked;
    int block_threshold; // Time in seconds to block the domain
    double current_time_on_domain; // Time in sechonds spent on the domain
    time_t last_time_packet_received;
    time_t last_time_blocked; 
} DomainInfo;

typedef struct {
    DomainInfo* arr;
    int count;
} DomainArray;

typedef struct {
    uint8_t hour_to_reset; // Hour of the day to reset the blocked domains
    uint8_t minute_to_reset; // Minute of the hour to reset the blocked domains
} Settings;


typedef enum {
    IPV4,
    IPV6
} IPVersion;

#endif