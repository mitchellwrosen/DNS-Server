#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>

#include "checksum.h"
#include "debug.h"
#include "dns_server.h"
#include "smartalloc.h"

int main(int argc, char** argv) {
   // set up signal handling

   DNSServer* server = new DNSServer();
   server->Run();

   delete server;
}

DNSServer::DNSServer()
      : port_("5003") {
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
   //struct sockaddr_storage client_addr;
   //socklen_t client_addr_len = sizeof(struct sockaddr_storage);

   if (HasDataToRead(sock_, 1, 0))
      std::cout << "Data to read" << std::endl;
   else
      std::cout << "No data to read" << std::endl;


}
