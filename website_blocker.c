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
#include "file_helper.h"

volatile sig_atomic_t interrupted = 0;
Settings global_settings = {15, 16}; // Default Settings

void block_domain(DomainInfo * domain){
    domain->is_blocked = true;
    domain->last_time_blocked = time(NULL);
    for (int i = 0; i < domain->ipv4s.count; i++) {
        block_ipv4(domain->ipv4s.arr[i]);
    }
    for (int i = 0; i < domain->ipv6s.count; i++) {
        block_ipv6(domain->ipv6s.arr[i]);
    }
}
void unblock_domain(DomainInfo * domain){
    domain->current_time_on_domain = 0;
    domain->is_blocked = false;
    domain->last_time_blocked = (time_t)0;
    domain->last_time_packet_received = (time_t)0;
    for (int i = 0; i < domain->ipv4s.count; i++) {
        unblock_ip(domain->ipv4s.arr[i], IPV4);
    }
    for (int i = 0; i < domain->ipv6s.count; i++) {
        unblock_ip(domain->ipv6s.arr[i], IPV6);
    }
}

void setup_domains(DomainArray* domains) {
    // Read domains from the config file.
    load_domain_array(domains, "domains.bin");

    // If the program was just booted we have to check when the domains were last blocked
    time_t current_time = time(NULL);

    for (int i = 0; i < domains->count; i++) {
        time_t last_time_blocked = domains->arr[i].last_time_blocked;
            // Get hours and minutes of the last block
        struct tm *tm_info = localtime(&last_time_blocked);
        int last_block_hour = tm_info->tm_hour;
        int last_block_minute = tm_info->tm_min;

        int hours_between_block_and_reset = global_settings.hour_to_reset - last_block_hour;
        int minutes_between_block_and_reset = global_settings.minute_to_reset - last_block_minute;
        int potential_reset = last_time_blocked + hours_between_block_and_reset * 3600 + minutes_between_block_and_reset * 60;

        if (domains->arr[i].is_blocked){
            if (last_time_blocked - current_time >= 24 * 3600 || current_time > potential_reset) {
                // If the last block was more than 24 hours ago, reset the domain OR if the current time is past the reset time
                unblock_domain(&domains->arr[i]);
            }
        } else {
            // We have to check if the domain was not blocked and clear it from time on the domain if the
            // current time is past the reset time. 
            if (current_time > potential_reset) {
                unblock_domain(&domains->arr[i]);
            }
        }
        
    }

}

void update_domain_ips(DomainInfo* domain) {
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

void unblock_domains(DomainArray* domains) {
    /*
    This function resets the blocked domains.
    */
    for (int i = 0; i < domains->count; i++) {
        unblock_domain(&domains->arr[i]);
    }
}

void add_domain(char * domain, uint block_threshold){
    DomainArray domains = {malloc(1 * sizeof(DomainInfo)), 1};
    domains.arr[0].domain = strdup(domain);
    domains.arr[0].ipv4s = (StringArray){NULL, 0};
    domains.arr[0].ipv6s = (StringArray){NULL, 0};
    get_ipv4_ipv6(domains.arr[0].domain, &domains.arr[0].ipv4s, &domains.arr[0].ipv6s);
    printf("Ips retrieved for domain %s:\n", domains.arr[0].domain);
    domains.arr[0].is_blocked = false;
    domains.arr[0].block_threshold = block_threshold;
    domains.arr[0].current_time_on_domain = 0;
    domains.arr[0].last_time_packet_received = (time_t)0;

    // Override the config file.
    save_domain_array(&domains, "domains.bin");
}

void free_domains(DomainArray* domains) {
    /*
    This function frees memory of domains.
    */

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


int try_block_domain(const char* ip, IPVersion ip_version, DomainArray* domains) {
    /*
    This function checks if the given IP is in the blocked domains list.
    */

   for(int i = 0; i < domains->count; i++) {
        StringArray ip_array;

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
    printf("Starting website blocker...\n");

    fflush(stdout);

    init_log("log.txt");

    signal(SIGINT, handle_sigint);

    DomainArray domains = {NULL, 0};

    printf("Setting up domains...\n");
    setup_domains(&domains);

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
    unblock_domains(&domains);
    free_domains(&domains);
    free(buffer);
    for (int i = 0; i < 2; i++) {
        free(src_dst_ips[i]);
    }
    free(src_dst_ips);
    close(sock_raw);

    printf("Exiting program.\n");
    return 0;
}


