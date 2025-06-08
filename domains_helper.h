#ifndef DOMAINS_HELPER_H
#define DOMAINS_HELPER_H
#include <stdio.h>
#include <stdlib.h>
#include "types.h"
#include "ip_helper.h"

void block_domain(DomainInfo * domain);
void unblock_domain(DomainInfo * domain);
void setup_domains(DomainArray* domains);
void update_domain_ips(DomainInfo* domain);
void unblock_domains(DomainArray* domains);
void free_domains(DomainArray* domains);
int try_block_domain(const char* ip, IPVersion ip_version, DomainArray* domains);
void get_ipv4_ipv6(const char* domain, StringArray* ipv4s, StringArray* ipv6s); 

#endif // DOMAINS_HELPER_H