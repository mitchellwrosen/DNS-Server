#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dns_server.h"
#include "checksum.h"
#include "smartalloc.h"

int main(int argc, char** argv) {
   // set up signal handling

   DNSServer server = new DNSServer();
   server.Run();
}

DNSServer::DNSServer()
      : port_("53") {
   struct addrinfo hints;

   // set up server hints struct
   memset(&hints, 0, sizeof(struct addrinfo));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_DGRAM;
   hints.ai_flags = AI_PASSIVE;

   // init server
   Init(port_, &hints);
}

void DNSServer::Run() {
   struct sockaddr_storage client_addr;
   socklet_t client_addr_len = sizeof(struct sockaddr_storage);



}
