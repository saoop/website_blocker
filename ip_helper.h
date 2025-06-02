#ifndef IP_HELPER_H
#define IP_HELPER_H

#include <stdio.h>
#include <stdlib.h>
#include "types.h"

/* Block an IPv4 address using iptables */
static inline void block_ipv4(const char *ip) {
    printf("Blocking IPv4: %s\n", ip);
    char command[256];
    snprintf(command, sizeof(command), "iptables -A INPUT -s %s -j DROP", ip);
    system(command);
}

/* Unblock an IPv4 address */
static inline void unblock_ipv4(const char *ip) {
    printf("Unblocking IPv4: %s\n", ip);
    char command[256];
    snprintf(command, sizeof(command), "iptables -D INPUT -s %s -j DROP", ip);
    system(command);
}

/* Block an IPv6 address using ip6tables */
static inline void block_ipv6(const char *ip) {
    printf("Blocking IPv6: %s\n", ip);
    char command[256];
    snprintf(command, sizeof(command), "ip6tables -A INPUT -s %s -j DROP", ip);
    system(command);
}

/* Unblock an IPv6 address */
static inline void unblock_ipv6(const char *ip) {
    printf("Unblocking IPv6: %s\n", ip);
    char command[256];
    snprintf(command, sizeof(command), "ip6tables -D INPUT -s %s -j DROP", ip);
    system(command);
}

static inline void block_ip(const char *ip, IPVersion ip_version){
    switch (ip_version)
        {
            case IPV4:
                block_ipv4(ip);
                break;

            case IPV6:
                block_ipv6(ip);
                break;
        }
}

static inline void unblock_ip(const char *ip, IPVersion ip_version){
    switch (ip_version)
        {
            case IPV4:
                unblock_ipv4(ip);
                break;

            case IPV6:
                unblock_ipv6(ip);
                break;
        }
}

#endif  // IP_HELPER_H
