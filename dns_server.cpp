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
#include "smartalloc.h"

#include "dns_server.h"
#include "dns_packet.h"

DnsServer* server;

int main(int argc, char** argv) {
   // check for root
   if (getuid() || geteuid()) {
      fprintf(stderr, "Must be root to run %s\n", argv[0]);
      exit(EXIT_FAILURE);
   }

   // set up signal handling
   struct sigaction sigact;
   memset(&sigact, 0, sizeof(struct sigaction));
   sigact.sa_handler = sigint_handler;
   SYSCALL(sigaction(SIGINT, &sigact, NULL), "sigaction");


   server = new DnsServer();
   server->Run();

   delete server;
}

void sigint_handler(int signum) {
   switch (signum) {
      case SIGINT:
         // clean dynamically allocated memory
         delete server;

         fprintf(stdout, "Server exiting cleanly.\n");
         exit(EXIT_FAILURE);
         break;
   }
}

DnsServer::DnsServer()
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

void DnsServer::Run() {
   //struct sockaddr_storage client_addr;
   //socklen_t client_addr_len = sizeof(struct sockaddr_storage);
   char* buf[1500]; 

   if (HasDataToRead(sock_)) {
      std::cout << "Data to read" << std::endl;

      DnsPacket mypacket(data);
      mypacket.Print();
/*      
      for (int i = 0; i < mypacket.queries(); ++i) {
         DnsPacket::Query query = mypacket.GetQuery();
         
      }

      for (int i = 0; i < mypacket.answer_rrs(); ++i) {
         Dns::ResourceRecord record = mypacket.GetResourceRecord();
         
      }

      for (int i = 0; i < mypacket.authority_rrs(); ++i) {
         Dns::ResourceRecord record;

      }

      for (int i = 0; i < mypacket.additional_rrS(); ++i) {
         Dns::ResourceRecord record;

      }
*/         
   } else {
      std::cout << "No data to read" << std::endl;
   }
}
