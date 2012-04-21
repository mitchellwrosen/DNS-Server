#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
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

const bool logging = true;

namespace dns_packet_constants = constants;

DnsServer::DnsServer()
      : port_("53") {
   // set up server hints struct
   struct addrinfo hints;

   memset(&hints, 0, sizeof(struct addrinfo));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_DGRAM;
   hints.ai_flags = AI_PASSIVE;

   // init server
   Server::Init(port_, &hints);
}

DnsServer::~DnsServer() {
}

void DnsServer::Run() {
   struct sockaddr_storage client_addr;
   socklen_t client_addr_len = sizeof(struct sockaddr_storage);

   // Main event loop
   if (Server::HasDataToRead(sock_)) {
      std::cout << "Data to read" << std::endl;

      int rlen;
      SYSCALL((rlen = recvfrom(sock_, buf_, ETH_DATA_LEN, 0,
            (struct sockaddr*) &client_addr, &client_addr_len)), "recvfrom");

      DnsPacket packet(buf_);
      packet.Print();

      // Check QR bit
      LOG1("qr_flag: %d", packet.qr_flag());
      if (packet.qr_flag()) {
         // Response
      }
      else {
         // New query
         DnsQuery query = packet.GetQuery();
         query.Print();

         // Respond to query
         Respond(query);
      }
   } else {
      std::cout << "No data to read" << std::endl;
   }
}

void Respond(DnsQuery query) {
   switch (query.type()) {
      if (cache_.get(query)) {
         //send_response
      }
      
      // not in cache
      else {
         // if recursive, query authority name server
         if (query.rd_()) {
         
         }

         // if iterative, respond with all we know
         else {
            do {
               cache_.get(DnsPacket::ShortenName(query.name()),
                          constants::type::NS,
                          query.clz());
            } while (/*cache_.get() == NULL*/);
         }
         
      }

      break;
   }
}
