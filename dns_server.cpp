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
#include "dns_query.h"
#include "dns_resource_record.h"

namespace constants = dns_packet_constants;

DnsServer::DnsServer()
      : port_("5003") {
   // set up server hints struct
   struct addrinfo hints;

   LOG << "Setting up hints struct" << std::endl;
   memset(&hints, 0, sizeof(struct addrinfo));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_DGRAM;
   hints.ai_flags = AI_PASSIVE;

   // init server
   LOG << "Initializing server" << std::endl;
   Server::Init(port_, &hints);
   LOG << "Server initialized" << std::endl;
}

DnsServer::~DnsServer() {
}

void DnsServer::Run() {
   struct sockaddr_storage client_addr;
   socklen_t client_addr_len = sizeof(struct sockaddr_storage);

   // Main event loop
   while (Server::HasDataToRead(sock_)) {
      LOG << "Has data to read" << std::endl;

      int rlen;
      SYSCALL((rlen = recvfrom(sock_, buf_, ETH_DATA_LEN, 0,
            (struct sockaddr*) &client_addr, &client_addr_len)), "recvfrom");

      DnsPacket packet(buf_);
      LOG << "Printing packet received (" << rlen << ") bytes)" << std::endl;
      packet.PrintHeader();

      // Check QR bit
      LOG << "qr_flag: " << packet.qr_flag() << std::endl;
      if (packet.qr_flag()) {
         // Response
      }
      else {
         // New query
         DnsQuery query = packet.GetQuery();
         LOG << "Printing packet's query:" << std::endl;
         query.Print();

         // Respond to query
         //Respond(query, packet.rd_flag());
      }
   } 
}

void DnsServer::Respond(DnsQuery query, bool recursive) {
   std::vector<DnsResourceRecord> answer_rrs;
   std::vector<DnsResourceRecord> authority_rrs;
   std::vector<DnsResourceRecord> additional_rrs;

   if (cache_.Get(query, &answer_rrs, &authority_rrs, &additional_rrs)) {
         //send_response
   }
      
   // not in cache
   else {
      // if recursive, query authority name server
      if (recursive) {
         
       
      }

      // if iterative, respond with all we know
      else {

      }
   }
}
