#ifndef IP_HELPER_H
#define IP_HELPER_H
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include "types.h"
#include <netdb.h> // For getaddrinfo and struct addrinfo
#include <netinet/ip.h>
#include <netinet/if_ether.h> // For Ethernet headers
#include <netinet/tcp.h>      // For TCP headers
#include <stdbool.h>
#include <time.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>

/* Block an IPv4 address using iptables */
void block_ipv4(const char *ip) {
    printf("Blocking IPv4: %s\n", ip);
    char command[256];
    snprintf(command, sizeof(command), "iptables -A INPUT -s %s -j DROP", ip);
    system(command);
}

/* Unblock an IPv4 address */
void unblock_ipv4(const char *ip) {
    printf("Unblocking IPv4: %s\n", ip);
    char command[256];
    snprintf(command, sizeof(command), "iptables -D INPUT -s %s -j DROP", ip);
    while(system(command) == 0); // This is just to make sure that it unblocks all rules (could add duplicate rules accidentaly)
}

/* Block an IPv6 address using ip6tables */
void block_ipv6(const char *ip) {
    printf("Blocking IPv6: %s\n", ip);
    char command[256];
    snprintf(command, sizeof(command), "ip6tables -A INPUT -s %s -j DROP", ip);
    system(command);
}

/* Unblock an IPv6 address */
void unblock_ipv6(const char *ip) {
    printf("Unblocking IPv6: %s\n", ip);
    char command[256];
    snprintf(command, sizeof(command), "ip6tables -D INPUT -s %s -j DROP", ip);
    while(system(command) == 0);
}

void block_ip(const char *ip, IPVersion ip_version){
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

void unblock_ip(const char *ip, IPVersion ip_version){
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


void get_ipv4_ipv6(const char* domain, StringArray* ipv4s, StringArray* ipv6s) {
    /*
    This function retrieves both IPv4 and IPv6 addresses for a given domain name.
    It fills the provided string arrays with the respective IP addresses.
    */

    printf("Retrieving IPs for domain: %s\n", domain);
    struct addrinfo hints, *res, *p;
    char ipstr6[INET6_ADDRSTRLEN];
    char ipstr4[INET_ADDRSTRLEN];
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(domain, NULL, &hints, &res) != 0) {
        perror("getaddrinfo error");
        return;
    }
    ipv4s->arr = NULL;
    ipv4s->count = 0;
    ipv6s->arr = NULL;
    ipv6s->count = 0;


    for (p = res; p != NULL; p = p->ai_next) {
        // void *addr;
        printf("Adding IPs to arrays...\n");

        if (p->ai_family == AF_INET) { // IPv4
            printf("IPv4 address found.\n");
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            // addr = &(ipv4->sin_addr);
            inet_ntop(p->ai_family, &(ipv4->sin_addr), ipstr4, sizeof ipstr4);
            printf("IPv4: %s\n", ipstr4);
            ipv4s->arr = realloc(ipv4s->arr, (ipv4s->count + 1) * sizeof(char*));
            ipv4s->arr[ipv4s->count++] = strdup(ipstr4);
        } else if (p->ai_family == AF_INET6) { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            // addr = &(ipv6->sin6_addr);
            inet_ntop(p->ai_family, &(ipv6->sin6_addr), ipstr6, sizeof ipstr6);
            ipv6s->arr = realloc(ipv6s->arr, (ipv6s->count + 1) * sizeof(char*));
            ipv6s->arr[ipv6s->count++] = strdup(ipstr6);
            printf("IPv6: %s\n", ipstr6);
        }
    }

    printf("Freeing addrinfo...\n");

    freeaddrinfo(res);
}

#endif  // IP_HELPER_H
