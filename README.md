# Domain blocker for Linux

A  simple productivity app. IP sniffer that blocks a domain after a cetrain threshold of time spent on the domain is reached.

I could not find a website blocker for linux, so decided to create my own, which also helped me deepen my knowledge of low level programming.

## How it works

A daemon (`website_blocker`) sniffs every packet on the machine with an `AF_PACKET` raw
socket, matches the source IP against the IPs of the domain. Then when the time threshold is reached, it inserts a rule into iptables.

A small CLI (`block_website_client`) adds domains to the watch
list and tells the running daemon to reload it over a unix socket at `/tmp/my_socket`.

## Build

```sh
make                      # builds the daemon: ./website_blocker
gcc -O2 block_website_client.c file_helper.c domains_helper.c \
    logging_helper.c ip_helper.c -o block_website_client
```

## Run

Both binaries read and write `domains.bin` and `log.txt` relative to the current
directory.

1. Start the daemon :

   ```sh
   sudo ./website_blocker
   ```
2. Add a domain and its daily allowance, in seconds (in a separate terminal):

   ```sh
   ./block_website_client instagram.com 1800
   ```
   This appends the domain to domains.bin file and notifies the daemon to reload it. The
3. Stop with `Ctrl+C` in the daemon's terminal.
