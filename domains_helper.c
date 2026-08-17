#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "types.h"
#include "ip_helper.h"
#include "file_helper.h"
#include "logging_helper.h"

Settings global_settings = {15, 16}; // Default Settings

#define MAX_IDLE_GAP_SECONDS 60

time_t last_reset_time(time_t now) {
    struct tm tm_reset;

    if (localtime_r(&now, &tm_reset) == NULL) {
        return 0;
    }

    tm_reset.tm_hour = global_settings.hour_to_reset;
    tm_reset.tm_min = global_settings.minute_to_reset;
    tm_reset.tm_sec = 0;
    tm_reset.tm_isdst = -1;

    time_t reset = mktime(&tm_reset);

    if (reset == (time_t)-1) {
        return 0;
    }

    if (reset > now) {
        tm_reset.tm_mday -= 1;
        tm_reset.tm_isdst = -1;
        reset = mktime(&tm_reset);
        if (reset == (time_t)-1) {
            return 0;
        }
    }

    return reset;
}


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

    free_domains(domains); // Free any previously allocated memory 

    load_domain_array(domains, "domains.bin");

    // If the program was just booted we have to check when the domains were last blocked
    time_t current_time = time(NULL);
    time_t last_reset = last_reset_time(current_time);

    for (int i = 0; i < domains->count; i++) {
        time_t reference_time = domains->arr[i].is_blocked
            ? domains->arr[i].last_time_blocked
            : domains->arr[i].last_time_packet_received;

        if (reference_time != 0 && reference_time < last_reset) {
            unblock_domain(&domains->arr[i]);
        }

        update_domain_ips(&domains->arr[i]);

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
        for (int j = 0; j < domains->arr[i].ipv6s.count; j++) {
            free(domains->arr[i].ipv6s.arr[j]);
        }
        free(domains->arr[i].ipv6s.arr);
    }
    free(domains->arr);
    domains->arr = NULL;
    domains->count = 0;


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
                    double gap = difftime(current_time, domains->arr[i].last_time_packet_received);
                    // If we have a gap between 2 packets -> probably away from domain.
                    if (gap > MAX_IDLE_GAP_SECONDS) {
                        gap = 0;
                    }
                    domains->arr[i].current_time_on_domain += gap;
                } else {
                    printf("First packet received for domain %s\n", domains->arr[i].domain);
                    domains->arr[i].current_time_on_domain = 1; // Initialize to 1 second if this is the first packet received
                }
                domains->arr[i].last_time_packet_received = current_time;

                // Update is_blocked
                if (domains->arr[i].current_time_on_domain > domains->arr[i].block_threshold) {
                    printf("Blocking domain %s for exceeding time threshold.\n", domains->arr[i].domain);
                    block_domain(&domains->arr[i]);
                    save_domain_array(domains, "domains.bin");
                }

                
                break;
            }
        }
    }
    return 0;
}