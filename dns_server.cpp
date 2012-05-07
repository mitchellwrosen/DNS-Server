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
#include <stack>
#include <vector>

#include "debug.h"
#include "checksum.h"
#include "smartalloc.h"

#include "dns_server.h"
#include "dns_packet.h"

namespace constants = dns_packet_constants;

DnsServer::DnsServer() : port_(53), port_str_("53") {
   // set up server hints struct
   struct addrinfo hints;

   LOG << "Setting up hints struct" << std::endl;
   memset(&hints, 0, sizeof(struct addrinfo));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_DGRAM;
   hints.ai_flags = AI_PASSIVE;

   // alloc cache
   cache_ = new DnsCache();


   // init server
   LOG << "Initializing server" << std::endl;
   Server::Init(port_str_, &hints);
   LOG << "Server initialized" << std::endl;
}

DnsServer::~DnsServer() {
   delete cache_;
}

/*
DnsServer::QueryInfo::QueryInfo(DnsQuery query,
                                RRVec& authority_rrs,
                                RRVec& additional_rrs) {
   QueryInfo(query, authority_rrs, additional_rrs);
}
*/

DnsServer::QueryInfo::QueryInfo(DnsQuery& query,
                                RRVec& authority_rrs,
                                RRVec& additional_rrs)
      : query_(query),
        authority_rrs_(authority_rrs),
        additional_rrs_(additional_rrs) {
}

DnsServer::ClientInfo::ClientInfo(struct sockaddr_storage client_addr,
                                  socklen_t client_addr_len,
                                  uint16_t id,
                                  DnsQuery& query,
                                  RRVec& authority_rrs,
                                  RRVec& additional_rrs)
      : client_addr_(client_addr),
        client_addr_len_(client_addr_len),
        id_(id) {
   query_info_stack_.push(QueryInfo(query, authority_rrs, additional_rrs));
}

bool DnsServer::ClientInfo::operator==(const uint16_t id) const {
   return id_ == id;
}

bool DnsServer::ClientInfo::operator<(const ClientInfo& client_info) const {
   return timeout_ > client_info.timeout_;
}

bool DnsServer::UpdateTimeout(uint16_t id) {
   ClientInfoVec::iterator it =
         std::find(client_info_vec_.begin(), client_info_vec_.end(), id);

   // Replace old timeout, if it exists
   if (it != client_info_vec_.end()) {
      it->timeout_ = time(NULL) + 2000;

      // Sort into heap
      std::make_heap(client_info_vec_.begin(), client_info_vec_.end());

      return true;
   }

   return false;
}

void DnsServer::Run() {
   struct sockaddr_storage client_addr;
   socklen_t client_addr_len = sizeof(struct sockaddr_storage);

   // Main event loop
   while (1) {
      // If timeout, query another authority server
      if (client_info_vec_.size() &&
          time(NULL) > client_info_vec_.front().timeout_) {
         LOG << "Timeout. Deleting top authority record and querying another "
               "server." << std::endl;
         ClientInfo* client_info = &client_info_vec_.front();
         RRVec& auth_rrs = client_info->query_info_stack_.top().authority_rrs_;

         auth_rrs.erase(auth_rrs.begin());

         // If there are no more authority servers to query, delete this client
         if (auth_rrs.empty()) {
            LOG << "Just erased last authority RR. Delete this ClientInfo and "
                  "simply don't respond." << std::endl;
            std::pop_heap(client_info_vec_.begin(), client_info_vec_.end());
            client_info_vec_.pop_back();
         } else {
            if (!UpdateTimeout(client_info->id_)) {
               LOG << "ERROR: id " << client_info->id_ <<
                     " not found in client info vec" << std::endl;
               exit(EXIT_FAILURE);
            }

            SendQueryUpstream(client_info);
         }
      }

      // 100 ms wait for data to come in
      if (Server::HasDataToRead(sock_, 0, 100)) {
         ReadIntoBuffer((struct sockaddr*) &client_addr, &client_addr_len);
         DnsPacket packet(buf_);

         DnsQuery query = packet.GetQuery();

         if (packet.qr_flag())
            CacheAllResourceRecords(packet, query);

         // Assume that the top QueryInfo of the current ClientInfo is
         // out-of-date and be refreshed. (This is not the case when this is
         // there is no ClientInfo for this client yet (first query)).

         RRVec answer_rrs;

         ClientInfo* cur_client_info;
         ClientInfoVec::iterator it = std::find(client_info_vec_.begin(),
                                                client_info_vec_.end(),
                                                packet.id());
         // "Special" case -- no ClientInfo for this client yet (first query)
         if (it == client_info_vec_.end()) {
            LOG << "First time query - attempting to respond with cache" <<
                  std::endl;
            RRVec authority_rrs;
            RRVec additional_rrs;

            // If cache hit or iterative-request, respond
            if (cache_->Get(query, &answer_rrs, &authority_rrs,
                  &additional_rrs) || !packet.rd_flag()) {
               int packet_len = DnsPacket::ConstructPacket(buf_, packet.id(),
                     true, packet.opcode(), false, false, packet.rd_flag(),
                     true, packet.rcode(), query, answer_rrs,
                     authority_rrs, additional_rrs);

               // TODO change the client addr
               SendBufferToAddr((struct sockaddr*) &client_addr,
                                client_addr_len,
                                packet_len);

               // Go back to listening for packets
               continue;
            }

            // Cache miss and recursive-request. Initialize ClientInfo.
            LOG << "First time query after cache miss -- creating ClientInfo"
                  << std::endl;

            // Push client info to vec
            client_info_vec_.push_back(ClientInfo(client_addr,
                                                  client_addr_len,
                                                  packet.id(),
                                                  query,
                                                  authority_rrs,
                                                  additional_rrs));

            // Save a pointer to the client just added
            cur_client_info = &(*(client_info_vec_.end()-1));

            // Update timeout, which sorts the vec
            if (!UpdateTimeout(packet.id())) {
               LOG << "ERROR: id " << packet.id() <<
                     " not found in client info vec" << std::endl;
               exit(EXIT_FAILURE);
            }
         } else {
            // Grab a pointer to the client
            cur_client_info = &(*it);

            // Grab a pointer to the query stack
            QueryInfoStack& cur_query_info_stack =
               cur_client_info->query_info_stack_;

            // If this was a response, and there are answers to a query that
            // wasn't the original, pop it query
            if (packet.qr_flag() &&
                packet.answer_rrs() &&
                cur_query_info_stack.size() > 1)
               cur_query_info_stack.pop();

            QueryInfo& cur_query_info = cur_query_info_stack.top();

            RRVec& authority_rrs = cur_query_info.authority_rrs_;
            RRVec& additional_rrs = cur_query_info.additional_rrs_;

            cur_query_info.authority_rrs_.clear();
            cur_query_info.additional_rrs_.clear();

            // Cache hit -- this will be the original query, because if there
            // were answers to another query (such as an A record of a NS we
            // needed), they would have been cached and then the QueryInfo
            // struct popped. The only QueryInfo struct *not* popped is the
            // original query.
            if (cache_->Get(query, &answer_rrs, &authority_rrs,
                  &additional_rrs)) {
               // Make sure the above comment is accurate with a sanity check
               if (cur_client_info->query_info_stack_.size() != 1) {
                  LOG << "About to send a response to client for a query other "
                        "than the original. Something's wrong. Abort." <<
                        std::endl;
                  exit(EXIT_FAILURE);
               }

               int packet_len = DnsPacket::ConstructPacket(buf_, packet.id(),
                     true, packet.opcode(), false, false, packet.rd_flag(),
                     true, packet.rcode(), query, answer_rrs, authority_rrs,
                     additional_rrs);

               // TODO change the client addr?
               SendBufferToAddr(
                     (struct sockaddr*) &cur_client_info->client_addr_,
                     cur_client_info->client_addr_len_,
                     packet_len);

               // Delete the current client info
               client_info_vec_.erase(it);

               // Go back to listening for packets
               continue;
            }
         }

         QueryInfo& cur_query_info = cur_client_info->query_info_stack_.top();

         // If we got a CNAME from cache, put it on the query info stack
         if (answer_rrs.size()) {
            DnsQuery temp_query(answer_rrs.begin()->data(),
                                query.type(),
                                query.clz());

            cur_client_info->query_info_stack_.push(
                  QueryInfo(temp_query,
                            cur_query_info.authority_rrs_,
                            cur_query_info.additional_rrs_));


            // Update timeout, which sorts the vec
            if (!UpdateTimeout(packet.id())) {
               LOG << "ERROR: id " << packet.id() <<
                     " not found in client info vec" << std::endl;
               exit(EXIT_FAILURE);
            }
         }

         SendQueryUpstream(cur_client_info);
      }
   }
}

void DnsServer::SendQueryUpstream(ClientInfo* client_info) {
   DnsResourceRecord* addl_rr;

   // Grab the top authority from the top QueryInfo and check to see if
   // its A record is in the additionals
   QueryInfo* query_info = &client_info->query_info_stack_.top();
   DnsResourceRecord& auth_rr = query_info->authority_rrs_.front();
   RRVec& addl_rrs = query_info->additional_rrs_;
   RRVec::iterator it;
   for (it = addl_rrs.begin(); it != addl_rrs.end(); ++it) {
      if (!it->name().compare(auth_rr.data()) &&
          it->type() == ntohs(constants::type::A)) { // todo i6
         break;
      }
   }

   // If we didn't find such an A rec, do a cache query to get the
   // right authority and A records. This query may end up with missing
   // additional information as well, in which case my program blows
   // up.
   if (it == addl_rrs.end()) {
      DnsQuery query2(auth_rr.data(),
                      htons(constants::type::A),
                      htons(constants::clz::IN));

      RRVec temp_answer_rrs;
      RRVec temp_authority_rrs;
      RRVec temp_additional_rrs;

      if (cache_->Get(query2, &temp_answer_rrs, &temp_authority_rrs,
            &temp_additional_rrs)) {
         LOG << "Broken cache." << std::endl;
         //exit(EXIT_FAILURE);
      }

      client_info->query_info_stack_.push(QueryInfo(query2,
                                                    temp_authority_rrs,
                                                    temp_additional_rrs));

      // Update timeout, which sorts the vec
      if (!UpdateTimeout(client_info->id_)) {
         LOG << "ERROR: id " << client_info->id_ <<
               " not found in client info vec" << std::endl;
         exit(EXIT_FAILURE);
      }

      // Grab the top authority from the top QueryInfo and check to see if
      // its A record is in the additionals. If it's not at this point,
      // we're completely fucked.
      query_info = &client_info->query_info_stack_.top();
      DnsResourceRecord& auth_rr = query_info->authority_rrs_.front();
      RRVec& addl_rrs = query_info->additional_rrs_;
      RRVec::iterator it;
      for (it = addl_rrs.begin(); it != addl_rrs.end(); ++it) {
         if (!it->name().compare(auth_rr.data()) &&
             it->type() == ntohs(constants::type::A)) { // todo i6
            break;
         }
      }

      if (it == addl_rrs.end()) {
         LOG << "No A record found. That's really bad news." << std::endl;
      } else {
         addl_rr = &(*it);
      }
   } else {
      addl_rr = &(*it);
   }

   // TODO i6
   struct sockaddr_in addr;
   socklen_t addrlen = sizeof(addr);
   addr.sin_family = AF_INET;
   addr.sin_port = htons(port_);
   memcpy(&addr.sin_addr, addl_rr->data(), sizeof(addr.sin_addr));

   SendQueryUpstream((struct sockaddr*) &addr, addrlen, query_info->query_,
         client_info->id_);
}

/*
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
         RRVec answer_rrs;
         RRVec authority_rrs;
         RRVec additional_rrs;

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
*/

/*
bool DnsServer::Resolve(DnsQuery& query, uint16_t id, uint16_t* response_code) {
   RRVec answer_rrs;
   RRVec authority_rrs;
   RRVec additional_rrs;

   if (cache_.Get(query, &answer_rrs, &authority_rrs, &additional_rrs))
      return true;

   LOG << "Cache miss - returned " << answer_rrs.size() << " answers, " <<
         authority_rrs.size() << " auth, " << additional_rrs.size() <<
         " additional." << std::endl;

   // Cache returned a CNAME for the original query. Change the current query
   // accordingly.
   if (answer_rrs.size()) {
      DnsQuery query2(answer_rrs.begin()->data(), query.type(), query.clz());
      return Resolve(query2, id, response_code);
   }

   RRVec::iterator authority_it;
   RRVec::iterator additional_it;
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
      addr.sin_port = htons(port_);
      memcpy(&addr.sin_addr, additional_it->data(), sizeof(addr.sin_addr));

      SendQueryUpstream((struct sockaddr*) &addr, addrlen, query);

      // Time out after 2 seconds and continue to the next authority
      if (Server::HasDataToRead(sock_, 2, 0)) {
         ReadIntoBuffer((struct sockaddr*) &addr, &addrlen);

         DnsPacket packet(buf_);
         LOG << "Got response from upstream server, id " << ntohs(packet.id());

         if (true) { //ntohs(packet.id()) == cur_id_) {
            LOG << " -- matched expected id" << std::endl;
            CacheAllResourceRecords(packet);

            // Save the response code from upstream server.
            if (packet.answer_rrs())
               *response_code = packet.rcode();

            return Resolve(query, id, response_code);
         } else {
            LOG << " -- did not match expected id " << cur_id_ <<
                  " -- ignoring." << std::endl;
         }
      }

      LOG << "Continuing to next authority after timeout" << std::endl;
      cur_id_++;
   } // Authority RR loop

   // Couldn't resolve query
   LOG << "Couldn't resolve query for " << query.name() << std::endl;
   return false;
}
*/

void DnsServer::CacheAllResourceRecords(DnsPacket& packet) {
   DnsQuery query = packet.GetQuery(); // Save query in case of SOAs
   CacheAllResourceRecords(packet, query);
}

void DnsServer::CacheAllResourceRecords(DnsPacket& packet, DnsQuery& query) {
   int num_rrs = packet.answer_rrs() + packet.authority_rrs() +
         packet.additional_rrs();

   for (int i = 0; i < num_rrs; ++i) {
      DnsResourceRecord record = packet.GetResourceRecord();

      if (ntohs(record.type()) == constants::type::SOA)
         cache_->Insert(query, record);
      else
         cache_->Insert(record);
   }
}

void DnsServer::SendQueryUpstream(struct sockaddr* addr, socklen_t addrlen,
      DnsQuery& query, uint16_t id) {

   char* p = DnsPacket::ConstructQuery(buf_, id,
         constants::opcode::Query, false, query);

   LOG << "Sending query " << query.ToString() << " with id " << id <<
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
