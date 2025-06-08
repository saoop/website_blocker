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
#include <sys/un.h>
#include "types.h"
#include "ip_helper.h"
#include "logging_helper.h"
#include "file_helper.h"
#include "domains_helper.h"

#define DOMAINS_FILE "domains.bin"
DomainArray domains = {NULL, 0};

volatile sig_atomic_t interrupted = 0;



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

void* ipc_listener(void* arg) {
    printf("Starting IPC listener...\n");
    int server_fd, client_fd;
    struct sockaddr_un addr;

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, "/tmp/my_socket");
    unlink(addr.sun_path);
    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 5);

    while (!interrupted) {
        client_fd = accept(server_fd, NULL, NULL); // blocks here!
        // Handle the request
        char buf[256];
        read(client_fd, buf, sizeof(buf));

        
        printf("Received request: %s\n", buf);
        if(strcmp(buf, DOMAINS_FILE_UPDATE) == 0) {
            // Handle the update request
            printf("Received update request for domains file.\n");
            // Reload the domains from the file
            setup_domains(&domains);
            if (domains.arr == NULL) {
                printf("Failed to reload domains.\n");
            } else {
                printf("Domains reloaded successfully. Count: %d\n", domains.count);
            }
        } else {
            printf("Unknown request: %s\n", buf);
        }
        // process `buf`
        close(client_fd);
    }
}

int main(){
    printf("Starting website blocker...\n");

    fflush(stdout);

    init_log("log.txt");

    signal(SIGINT, handle_sigint);


    printf("Setting up domains...\n");
    setup_domains(&domains);

    printf("Domains retrieved.\n");

    if (domains.arr == NULL) {
        printf("Failed to resolve domains.\n");
        return 1;
    }


    // Create a child thread for processing requests (adding new domains)
    pthread_t client_thread;
    pthread_create(&client_thread, NULL, (void*)ipc_listener, NULL);


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

    pthread_kill(client_thread, NULL);

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


