#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include "types.h"

void save_string(FILE *f, const char *str) {
    int len = strlen(str);
    fwrite(&len, sizeof(int), 1, f);
    fwrite(str, sizeof(char), len, f);
}

void save_string_array(FILE *f, StringArray *sa) {
    fwrite(&sa->count, sizeof(int), 1, f);
    for (int i = 0; i < sa->count; i++) {
        save_string(f, sa->arr[i]);
    }
}

void save_domain_array(const DomainArray *da, const char *filename) {
    FILE *f = fopen(filename, "wb");
    if (!f) return;

    fwrite(&da->count, sizeof(int), 1, f);
    for (int i = 0; i < da->count; i++) {
        DomainInfo *d = &da->arr[i];

        save_string(f, d->domain);
        save_string_array(f, &d->ipv4s);
        save_string_array(f, &d->ipv6s);
        fwrite(&d->is_blocked, sizeof(bool), 1, f);
        fwrite(&d->block_threshold, sizeof(int), 1, f);
        fwrite(&d->current_time_on_domain, sizeof(double), 1, f);
        fwrite(&d->last_time_packet_received, sizeof(time_t), 1, f);
        fwrite(&d->last_time_blocked, sizeof(time_t), 1, f);
    }

    fclose(f);
}

char *load_string(FILE *f) {
    int len;
    fread(&len, sizeof(int), 1, f);
    char *str = (char *)malloc(len + 1);
    fread(str, sizeof(char), len, f);
    str[len] = '\0';
    return str;
}

void load_string_array(FILE *f, StringArray *sa) {
    fread(&sa->count, sizeof(int), 1, f);
    sa->arr = (char**) malloc(sizeof(char *) * sa->count);
    for (int i = 0; i < sa->count; i++) {
        sa->arr[i] = load_string(f);
    }
}

void load_domain_array(DomainArray *da, const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return;

    printf("Loading domains from file: %s\n", filename);

    fread(&da->count, sizeof(int), 1, f);

    printf("Number of domains to load: %d\n", da->count);

    da->arr = (DomainInfo*)malloc(sizeof(DomainInfo) * da->count);

    printf("Number of domains loaded: %d\n", da->count);

    for (int i = 0; i < da->count; i++) {
        DomainInfo *d = &da->arr[i];

        d->domain = load_string(f);
        load_string_array(f, &d->ipv4s);
        load_string_array(f, &d->ipv6s);
        fread(&d->is_blocked, sizeof(bool), 1, f);
        fread(&d->block_threshold, sizeof(int), 1, f);
        fread(&d->current_time_on_domain, sizeof(double), 1, f);
        fread(&d->last_time_packet_received, sizeof(time_t), 1, f);
        fread(&d->last_time_blocked, sizeof(time_t), 1, f);
    }

    fclose(f);
}
