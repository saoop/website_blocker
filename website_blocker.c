// First get the IPs from a DNS query
// Update the ips.json with the IPs of the domains
// Third, sniff the packets and block the IPS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h> // For Ethernet headers
#include <stdbool.h>
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
    string_array ips;
    bool is_blocked;
    int block_threshold; // Time in seconds to block the domain
    double current_time_on_domain; // Time in sechonds spent on the domain
    time_t last_time_packet_received;
} domain_info;

typedef struct {
    domain_info* arr;
    int count;
} domain_array;

string_array get_ips(const char* domain) {
    /*
    This function retrieves IP addresses for a given domain name.
    */
    string_array result = {NULL, 0};

    struct hostent *host_entry;
    struct in_addr **addr_list;
    int i = 0;

    host_entry = gethostbyname(domain);
    if (host_entry == NULL) {
        perror("gethostbyname error");
        return result;
    }

    addr_list = (struct in_addr **)host_entry->h_addr_list;
    while (addr_list[i] != NULL) i++;

    result.arr = malloc(i * sizeof(char*));

    for (int j = 0; j < i; j++) {
        result.arr[j] = strdup(inet_ntoa(*addr_list[j]));
    }
    
    result.count = i;
    return result;
}

domain_array get_domain_infos(){
    // Later use a config file for now just hardcode the values
    domain_array domains = {malloc(1 * sizeof(domain_info)), 1};
    domains.arr[0].domain = strdup("example.com");
    domains.arr[0].ips = get_ips(domains.arr[0].domain);
    domains.arr[0].is_blocked = false;
    domains.arr[0].block_threshold = 10;
    domains.arr[0].current_time_on_domain = 0;
    domains.arr[0].last_time_packet_received = (time_t)0;

    return domains;
}

void on_boot(){
    // Check for current time?
    // if a domain was blocked a day before, reset the timer
}

void block_domain(char * ip){
    printf("Blocking source IP: %s\n", ip);
    char command[256];
    snprintf(command, sizeof(command), "iptables -A INPUT -s %s -j DROP", ip);
    system(command);

    // TODO set a timer? interrupt to unblock the domain?
}

int check_in_blocked_domains(const char* ip, domain_array domains) {
    /*
    This function checks if the given IP is in the blocked domains list.
    */
    for(int i = 0; i < domains.count; i ++){
        for (int j = 0; j < domains.arr[i].ips.count; j++){
            if (strcmp(domains.arr[i].ips.arr[j], ip) == 0) {
                if (domains.arr[i].is_blocked == 1){
                    block_domain(ip);
                    return 1;
                }
                
                // Update time spent on domain
                time_t current_time = time(NULL);

                if (domains.arr[i].last_time_packet_received != 0){
                    domains.arr[i].current_time_on_domain += difftime(current_time, domains.arr[i].last_time_packet_received);
                }
                else{
                    domains.arr[i].current_time_on_domain = 0;
                }
                domains.arr[i].last_time_packet_received = current_time;

                // Update is_blocked
                if(domains.arr[i].current_time_on_domain > domains.arr[i].block_threshold){
                    domains.arr[i].is_blocked = true;
                }

                //TODO an optimization: always put the most recently used ip at the beginning of the array.
                
                // We don't need to check any other ips of this domain
                break;
            }
        }
    }
    return 0;
}

int process_packet(unsigned char* buffer, int size, char** src_dst_ips) {
    /*
    This function processes a packet and extracts source and destination IP addresses.
    */
    struct ethhdr *eth = (struct ethhdr*)buffer;
    if (ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->saddr, src, sizeof(src));
        inet_ntop(AF_INET, &iph->daddr, dst, sizeof(dst));
        src_dst_ips[0] = strdup(src);
        src_dst_ips[1] = strdup(dst);
        return 0;
    }
    return 1;
}

int main(){
    const char* domain = "example.com"; // Replace with the target domain
    int count = 0;

    domain_array domains = get_domain_infos();

    // char** ips = get_ips(domain, &count);

    if (domains.arr == NULL) {
        printf("Failed to resolve domains.\n");
        return 1;
    }

    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socket Error");
        return 1;
    }

    unsigned char *buffer = (unsigned char *)malloc(65536);
    struct sockaddr saddr;
    int saddr_size = sizeof(saddr);

    char** src_dst_ips = malloc(2 * sizeof(char*));
    while (1) {
            int data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t*)&saddr_size);
            if (data_size < 0) {
                perror("Recvfrom error");
                return 1;
            }

            if (process_packet(buffer, data_size, src_dst_ips) == 0) {
                // Successfully processed the packet and extracted IPs
                printf("Packet from %s to %s\n", src_dst_ips[0], src_dst_ips[1]);
                if(check_in_blocked_domains(src_dst_ips[0], domains)) {
                    
                }
                if(check_in_blocked_domains(src_dst_ips[1], domains)) {
                    // Here you would implement the blocking logic, e.g., using iptables
                }
            } else {
                // Not an IP packet or error in processing
                continue;
            }
    }


    //TODO exit gracefully.
    // TODO deallocate memory for domains.


    return 0;
}


