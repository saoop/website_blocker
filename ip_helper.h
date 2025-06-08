#ifndef IP_HELPER_H
#define IP_HELPER_H

void block_ipv4(const char *ip);
void unblock_ipv4(const char *ip);
void block_ipv6(const char *ip);  
void unblock_ipv6(const char *ip);
void block_ip(const char *ip, IPVersion ip_version);
void unblock_ip(const char *ip, IPVersion ip_version);
void get_ipv4_ipv6(const char* domain, StringArray* ipv4s, StringArray* ipv6s);

#endif  // IP_HELPER_H