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

DnsServer::DnsServer() : port_("53"), cur_id_(0) {
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
         LOG << "Query: " << query.ToString() << std::endl;

         uint16_t response_code = constants::response_code::NoError;

         // If recursive, get answer into cache
         if (packet.rd_flag())
            Resolve(query, packet.id(), &response_code);

         // Respond
         std::set<DnsResourceRecord> answer_rrs;
         std::set<DnsResourceRecord> authority_rrs;
         std::set<DnsResourceRecord> additional_rrs;

         // Don't care about return value at this point -- we tried our best
         cache_.Get(query, &answer_rrs, &authority_rrs, &additional_rrs);
         int packet_len = DnsPacket::ConstructPacket(buf_, packet.id(), true,
               packet.opcode(), false, false, packet.rd_flag(), true,
               response_code, query, answer_rrs, authority_rrs, additional_rrs);
         SendBufferToAddr((struct sockaddr*) &client_addr, client_addr_len,
               packet_len);
      }
   }
}

bool DnsServer::Resolve(DnsQuery& query, uint16_t id, uint16_t* response_code) {
   std::set<DnsResourceRecord> answer_rrs;
   std::set<DnsResourceRecord> authority_rrs;
   std::set<DnsResourceRecord> additional_rrs;

   if (cache_.Get(query, &answer_rrs, &authority_rrs, &additional_rrs))
      return true;

   LOG << "Cache miss - returned " << answer_rrs.size() << " answers, " <<
         authority_rrs.size() << " auth, " << additional_rrs.size() <<
         " additional." << std::endl;

   // Cache returned a CNAME for the original query. Change the current query
   // accordingly.
   if (answer_rrs.size())
      query = DnsQuery(answer_rrs.begin()->data(), query.type(), query.clz());

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
             additional_it->type() == ntohs(constants::type::A)) // TODO i6
            break;
      }

      // Server didn't provide relevant additional information
      if (additional_it == additional_rrs.end()) {
         // If we successfully resolve it ourself, re-try the original query
         DnsQuery query2(authority_it->data(), htons(constants::type::A),
               htons(constants::clz::IN));
         if (Resolve(query2, id, response_code))
            return Resolve(query, id, response_code);

         // Otherwise, continue on to the next authority record
         else
            continue;
      }

      // Query upstream with relevant additional information
      // Prepare sockaddr_in for upstream server
      // TODO i6 compatibility
      struct sockaddr_in addr;
      socklen_t addrlen = sizeof(addr);
      addr.sin_family = AF_INET;
      addr.sin_port = htons(53);
      memcpy(&addr.sin_addr, additional_it->data(), addrlen);

      SendQueryUpstream((struct sockaddr*) &addr, addrlen, query);

      // Time out after 2 seconds and continue to the next authority
      if (Server::HasDataToRead(sock_, 2, 0)) {
         ReadIntoBuffer((struct sockaddr*) &addr, &addrlen);

         DnsPacket packet(buf_);
         LOG << "Got response from upstream server, id " << ntohs(packet.id());

         if (ntohs(packet.id()) == cur_id_) {
            LOG << " -- matched expected id" << std::endl;
            CacheAllResourceRecords(packet);

            if (packet.answer_rrs()) {
               // TODO check if answer_rrs() contains |query|, or otherwise it
               // contains just a CNAME. I think this can be accomplished by
               // simply calling Resolve() from here, so I'll try it.

               // Save the response code from upstream server.
               *response_code = packet.rcode();
               //return Resolve(query, id, response_code);
               return true;
            } else {
               return Resolve(query, id, response_code);
            }
         } else {
            LOG << " -- did not match expected id " << cur_id_ << " -- ignoring."
                  << std::endl;
         }
      }

      LOG << "Continuing to next authority after timeout" << std::endl;
      cur_id_++;
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

void DnsServer::SendQueryUpstream(struct sockaddr* addr, socklen_t addrlen,
      DnsQuery& query) {

   char* p = DnsPacket::ConstructQuery(buf_, htons(cur_id_),
         constants::opcode::Query, false, query);

   LOG << "Sending query " << query.ToString() << " with id " << cur_id_ <<
         " upstream." << std::endl;
   SendBufferToAddr(addr, addrlen, p - buf_);
}

void DnsServer::SendBufferToAddr(struct sockaddr* addr, socklen_t addrlen,
      int datalen) {
   // intentionally not error-checked
   sendto(sock_, buf_, datalen, 0, addr, addrlen);

   // TODO i6
   char* ip_dots_and_numbers =
         inet_ntoa(((struct sockaddr_in*) addr)->sin_addr);
   LOG << "Sent " << datalen << " bytes upstream to " << ip_dots_and_numbers <<
         std::endl;
}

int DnsServer::ReadIntoBuffer(struct sockaddr* client_addr,
                              socklen_t* client_addr_len) {
   int rlen;
   SYSCALL((rlen = recvfrom(sock_, buf_, ETH_DATA_LEN, 0,
         client_addr, client_addr_len)), "recvfrom");
   LOG << "Read " << rlen << " bytes into buffer." << std::endl;
   return rlen;
}
