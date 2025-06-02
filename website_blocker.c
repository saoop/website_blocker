// First get the IPs from a DNS query
// Update the ipv4s.json with the IPs of the domains
// Third, sniff the packets and block the IPS
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h> // For Ethernet headers
#include <netinet/tcp.h>      // For TCP headers
#include <stdbool.h>
#include <time.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include "types.h"
#include "ip_helper.h"
#include "logging_helper.h"



volatile sig_atomic_t interrupted = 0;
settings global_settings = {0, 0}; // Default settings

void get_ipv4_ipv6(const char* domain, string_array* ipv4s, string_array* ipv6s) {
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

domain_array get_domain_infos(){
    // Later use a config file for now just hardcode the values
    printf("Retrieving domain information...\n");
    domain_array domains = {malloc(1 * sizeof(domain_info)), 1};
    domains.arr[0].domain = strdup("example.com");
    // domains.arr[0].ipv4s = get_ips(domains.arr[0].domain);
    domains.arr[0].ipv4s = (string_array){NULL, 0};
    domains.arr[0].ipv6s = (string_array){NULL, 0};
    get_ipv4_ipv6(domains.arr[0].domain, &domains.arr[0].ipv4s, &domains.arr[0].ipv6s);
    printf("Ips retrieved for domain %s:\n", domains.arr[0].domain);
    domains.arr[0].is_blocked = false;
    domains.arr[0].block_threshold = 2;
    domains.arr[0].current_time_on_domain = 0;
    domains.arr[0].last_time_packet_received = (time_t)0;

    return domains;
}

void update_domain_ips(domain_info* domain) {
    /*
    This function updates the IPs of a given domain.
    It retrieves the current IPs and updates the domain's IPs array.
    */
    
    // Free old IPs and remove iptables rules for old IPs

    // IPv4s
    for (int i = 0; i < domain->ipv4s.count; i++) {
        unblock_ipv4(domain->ipv4s.arr[i]);
        free(domain->ipv4s.arr[i]);
    }
    free(domain->ipv4s.arr);

    // IPv6s
    for (int i = 0; i < domain->ipv6s.count; i++) {
        unblock_ipv6(domain->ipv6s.arr[i]);
        free(domain->ipv6s.arr[i]);
    }
    free(domain->ipv6s.arr);

    // Get new domain's IPs
    get_ipv4_ipv6(domain->domain, &domain->ipv4s, &domain->ipv6s);

    // Update iptables rules
    if (domain->is_blocked) {
        // If the domain is blocked, block the new IPs as well
        for (int i = 0; i < domain->ipv4s.count; i++) {
            block_ipv4(domain->ipv4s.arr[i]);
        }

        for (int i = 0; i < domain->ipv6s.count; i++) {
            block_ipv6(domain->ipv6s.arr[i]);
        }
    }
}

void reset_domains(domain_array* domains) {
    /*
    This function resets the blocked domains.
    */
    for (int i = 0; i < domains->count; i++) {
        domains->arr[i].is_blocked = false;
        domains->arr[i].current_time_on_domain = 0;
        domains->arr[i].last_time_packet_received = (time_t)0;
        for(int j = 0; j < domains->arr[i].ipv4s.count; j++) {
            unblock_ipv4(domains->arr[i].ipv4s.arr[j]);
        }
    }
}

void clean_domains(domain_array* domains) {
    /*
    This function is called when the program exits.
    It resets the blocked domains and removes any blocking rules from iptables.
    */
    reset_domains(domains);

    // Free allocated memory
    for (int i = 0; i < domains->count; i++) {
        free(domains->arr[i].domain);
        for (int j = 0; j < domains->arr[i].ipv4s.count; j++) {
            free(domains->arr[i].ipv4s.arr[j]);
        }
        free(domains->arr[i].ipv4s.arr);
    }
    free(domains->arr);


    printf("Cleanup of domains completed.\n");
}


int try_block_domain(const char* ip, IPVersion ip_version, domain_array* domains) {
    /*
    This function checks if the given IP is in the blocked domains list.
    */

   for(int i = 0; i < domains->count; i++) {
        string_array ip_array;

        switch (ip_version)
        {
            case IPV4:
                ip_array = domains->arr[i].ipv4s;
                break;

            case IPV6:
                ip_array = domains->arr[i].ipv6s;
                break;
        }

        for (int j = 0; j < ip_array.count; j++) {

            char log_message[256];
            snprintf(log_message, sizeof(log_message), "Checking IP: %s against domain %s IP: %s", ip, domains->arr[i].domain, ip_array.arr[j]);
            write_log(log_message);

            if (strcmp(ip_array.arr[j], ip) == 0) {
                printf("IP %s found in domain %s\n", ip, domains->arr[i].domain);
                snprintf(log_message, sizeof(log_message), "IP %s found in domain %s\n", ip, domains->arr[i].domain);
                write_log(log_message);

                if (domains->arr[i].is_blocked == 1) {
                    return 1;
                }
                
                // Update time spent on domain
                time_t current_time = time(NULL);

                if (domains->arr[i].last_time_packet_received != 0) {
                    domains->arr[i].current_time_on_domain += difftime(current_time, domains->arr[i].last_time_packet_received);
                } else {
                    printf("First packet received for domain %s\n", domains->arr[i].domain);
                    domains->arr[i].current_time_on_domain = 1; // Initialize to 1 second if this is the first packet received
                }
                domains->arr[i].last_time_packet_received = current_time;

                // Update is_blocked
                if (domains->arr[i].current_time_on_domain > domains->arr[i].block_threshold) {
                    printf("Blocking domain %s for exceeding time threshold.\n", domains->arr[i].domain);
                    domains->arr[i].is_blocked = true;
                    block_ip(ip, ip_version);
                }

                
                break;
            }
        }
    }
    return 0;
}

void on_startup() {
    /*
    This function is used to clean up any previous iptables rules
    and set up the initial state of the program.
    It should be called at the start of the program.
    */

    printf("Cleaning up previous iptables rules...\n");
    // Clear all previous rules

    printf("Website Blocker started.\n");
}


int process_packet(unsigned char* buffer, int size, char** ip,IPVersion * ip_version) {
    struct ethhdr *eth = (struct ethhdr*)buffer;
    uint16_t eth_type = ntohs(eth->h_proto);

    if (eth_type == ETH_P_IP){

        struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->saddr, src, sizeof(src));
        inet_ntop(AF_INET, &iph->daddr, dst, sizeof(dst));

        *ip = strdup(src);
        *ip_version = IPV4;
        return 0;

    } else if (eth_type == ETH_P_IPV6){
        struct ip6_hdr *ip6 = (struct ip6_hdr*)(buffer + sizeof(struct ethhdr));        
        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];

        if (!inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src))) {
            perror("inet_ntop src");
            return 1; 
        }   
        if (!inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst))) {
            perror("inet_ntop dst");
            return 1;
        }
        *ip = strdup(src);
        *ip_version  = IPV6;
        return 0;
    }
    return 1;  // Ignore other packets
}


void handle_sigint(int sig) {
    printf("\nCaught SIGINT (Ctrl+C)! Cleaning up...\n");
    interrupted = 1;
}


int main(){
    fflush(stdout);
    init_log("log.txt");

    signal(SIGINT, handle_sigint);
    printf("Starting website blocker...\n");
    domain_array domains = get_domain_infos();
    printf("Domains retrieved.\n");
    if (domains.arr == NULL) {
        printf("Failed to resolve domains.\n");
        return 1;
    }

    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socket Error");
        return 1;
    }
    printf("Socket created successfully.\n");
    unsigned char *buffer = (unsigned char *)malloc(65536);
    struct sockaddr saddr;
    int saddr_size = sizeof(saddr);

    char * ip = NULL;

    IPVersion ip_version = IPV4;

    char** src_dst_ips = malloc(2 * sizeof(char*));
    while (!interrupted) {
            int data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t*)&saddr_size);
            if (data_size < 0) {
                perror("Recvfrom error");
                return 1;
            }

            if (process_packet(buffer, data_size, &ip, &ip_version) == 0) {
                try_block_domain(ip, ip_version, &domains);
                free(ip);
            } else {
                // Not an IP packet or error in processing
                continue;
            }
    }

    // Cleanup
    clean_domains(&domains);
    free(buffer);
    for (int i = 0; i < 2; i++) {
        free(src_dst_ips[i]);
    }
    free(src_dst_ips);
    close(sock_raw);

    printf("Exiting program.\n");
    return 0;
}


