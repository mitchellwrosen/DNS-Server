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

#include <algorithm>
#include <iostream>
#include <set>

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

int DnsServer::ReadIntoBuffer() {
   struct sockaddr addr;
   socklen_t addr_len;
   return ReadIntoBuffer(&addr, &addr_len);
}

int DnsServer::ReadIntoBuffer(struct sockaddr* client_addr,
                              socklen_t* client_addr_len) {
   int rlen;
   SYSCALL((rlen = recvfrom(sock_, buf_, ETH_DATA_LEN, 0,
         client_addr, client_addr_len)), "recvfrom");
   LOG << "Read " << rlen << " bytes into buffer." << std::endl;
   return rlen;
}

void DnsServer::Run() {
   struct sockaddr_storage client_addr;
   socklen_t client_addr_len = sizeof(struct sockaddr_storage);

   // Main event loop
   while (Server::HasDataToRead(sock_)) {
      LOG << "Has data to read" << std::endl;

      ReadIntoBuffer((struct sockaddr*) &client_addr, &client_addr_len);

      DnsPacket packet(buf_);
      packet.PrintHeader();

      // Check QR bit
      if (packet.qr_flag()) {
         // Response
         // Cache all RRs
         // This will never be the case for milestone 1
         LOG << "ERROR: RESPONSE RECEIVED (shouldnt happen in milestone 1)" <<
               std::endl;
      }
      else {
         // New query
         DnsQuery query = packet.GetQuery();
         LOG << "Printing packet's query:" << std::endl;
         query.Print();

         // If recursive, get answer into cache
         if (packet.rd_flag())
            Resolve(query, packet.id());

         //Respond
      }
   }
}

bool DnsServer::Resolve(DnsQuery query, uint16_t id) {
   std::set<DnsResourceRecord> answer_rrs;
   std::set<DnsResourceRecord> authority_rrs;
   std::set<DnsResourceRecord> additional_rrs;

   if (cache_.Get(query, &answer_rrs, &authority_rrs, &additional_rrs))
      return true;

   std::set<DnsResourceRecord>::iterator authority_it;
   std::set<DnsResourceRecord>::iterator additional_it;
   for (authority_it = authority_rrs.begin();
        authority_it != authority_rrs.end();
        ++authority_it) {
      for (additional_it = additional_rrs.begin();
           additional_it != additional_rrs.end();
           ++additional_it) {
         // Check it the server provided relevant additional information
         if (!additional_it->name().compare(authority_it->data()) &&
             additional_it->type() == ntohs(constants::type::A))
            break;
      }

      // Server didn't provide relevant additional information
      if (additional_it == additional_rrs.end()) {
         // If we successfully resolve it ourself, re-try the original query
         if (Resolve(DnsQuery(authority_it->data(),
                              htons(constants::type::A),
                              htons(constants::clz::IN)),
                     id))
            return Resolve(query, id);

         // Otherwise, continue on to the next authority record
         else
            continue;
      }

      // Query upstream with relevant additional information
      SendQuery(additional_it->data(), 4, query, id);

      // Time out after 2 seconds and continue to the next authority
      if (Server::HasDataToRead(sock_, 2, 0)) {
         LOG << "Got response from upstream server" << std::endl;

         ReadIntoBuffer();
         DnsPacket packet(buf_);
         CacheAllResourceRecords(packet);
         if (packet.answer_rrs())
            return true;
         return Resolve(query, id);
      }

      LOG << "Continuing to next authority after timeout" << std::endl;
   } // Authority RR loop

   // Couldn't resolve query
   LOG << "Couldn't resolve query for " << query.name() << std::endl;
   return false;
}

void DnsServer::CacheAllResourceRecords(DnsPacket& packet) {
   packet.GetQuery(); // Consume query, advance cur_ pointer
   int num_rrs = packet.answer_rrs() + packet.authority_rrs() +
         packet.additional_rrs();

   for (int i = 0; i < num_rrs; ++i) {
      DnsResourceRecord record = packet.GetResourceRecord();
      cache_.Insert(record);
   }
}

void DnsServer::SendQuery(char* ip, int iplen, DnsQuery& query,
      uint16_t id) {
   char* p = DnsPacket::ConstructQuery(buf_, id, constants::opcode::Query,
         false, query);
   SendBufferToIp(ip, iplen, p - buf_);
}

void DnsServer::SendBufferToIp(char* ip, int iplen, int datalen) {
   int sock;
   struct addrinfo hints, *servinfo, *p;

   memset(&hints, 0, sizeof(struct addrinfo));
   hints.ai_family = AF_INET;
   hints.ai_socktype = SOCK_DGRAM;

   int ret;
   if ((ret = getaddrinfo(ip, "53", &hints, &servinfo))) {
      std::cerr << "getaddrinfo: " << gai_strerror(ret) << std::endl;
      return;
   }

   for (p = servinfo; p != NULL; p = p->ai_next) {
      if (-1 == (sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol))) {
         perror("socket");
         continue;
      }
      break;
   }

   if (!p) {
      std::cerr << "failed to bind to socket" << std::endl;
      return;
   }

   // intentionally not error-checked
   sendto(sock, buf_, datalen, 0, p->ai_addr, iplen);//p->ai_addrlen);
   LOG << "Sent " << datalen << " bytes upstream." << std::endl;

   close(sock);
}
