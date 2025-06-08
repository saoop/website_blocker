#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "types.h"
#include "file_helper.h"
#include "domains_helper.h"

int main(int argc, char **argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <domain> <threshold in seconds>\n", argv[0]);
        return 1;
    }

    printf("Adding domain: %s with threshold: %s seconds\n", argv[1], argv[2]);

    char * domain = argv[1];
    int threshold = atoi(argv[2]);

    printf("Domain: %s, Threshold: %d\n", domain, threshold);

    DomainArray domains = {NULL, 0};

    load_domain_array(&domains, "domains.bin");

    printf("Loaded %d domains from file.\n", domains.count);

    domains.arr = realloc(domains.arr, sizeof(DomainInfo) * (++domains.count));
    domains.arr[domains.count - 1].domain = strdup(domain);
    domains.arr[domains.count - 1].block_threshold = threshold;
    domains.arr[domains.count - 1].is_blocked = false;
    domains.arr[domains.count - 1].current_time_on_domain = 0.0;
    domains.arr[domains.count - 1].last_time_packet_received = 0;
    domains.arr[domains.count - 1].last_time_blocked = 0;
    domains.arr[domains.count - 1].ipv4s.arr = NULL;
    domains.arr[domains.count - 1].ipv4s.count = 0;
    domains.arr[domains.count - 1].ipv6s.arr = NULL;
    domains.arr[domains.count - 1].ipv6s.count = 0;

    save_domain_array(&domains, "domains.bin");

    printf("Domain %s added with threshold %d seconds.\n", domain, threshold);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, "/tmp/my_socket");

    connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    write(fd, DOMAINS_FILE_UPDATE, 23);
    close(fd);

    printf("Sent update to IPC server.\n");

    // Free allocated memory
    free_domains(&domains);

    return 0;
}

