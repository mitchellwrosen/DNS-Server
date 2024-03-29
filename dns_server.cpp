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
#include <list>

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
   hints.ai_family = AF_INET6;
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

DnsServer::QueryInfo::QueryInfo(DnsQuery& query,
                                RRVec& authority_rrs,
                                RRVec& additional_rrs)
      : query_(query),
        authority_rrs_(authority_rrs),
        additional_rrs_(additional_rrs) {
}

DnsServer::ClientInfo::ClientInfo(struct sockaddr_in6 client_addr,
                                  uint16_t id,
                                  DnsQuery& query,
                                  RRVec& authority_rrs,
                                  RRVec& additional_rrs)
      : client_addr_(client_addr),
        id_(id) {
   query_info_list_.push_back(QueryInfo(query, authority_rrs, additional_rrs));
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
      it->timeout_ = time(NULL) + 2;

      // Sort into heap
      std::make_heap(client_info_vec_.begin(), client_info_vec_.end());

      return true;
   }

   return false;
}

DnsServer::ClientInfoVec::iterator DnsServer::GetClient(uint16_t id) {
   return std::find(client_info_vec_.begin(),
                    client_info_vec_.end(),
                    id);
}

bool DnsServer::RemoveClient(uint16_t id) {
   return RemoveClient(GetClient(id));
}

bool DnsServer::RemoveClient(ClientInfoVec::iterator it) {
   if (it != client_info_vec_.end()) {
      client_info_vec_.erase(it);
      return true;
   }

   return false;
}

void DnsServer::Run() {
   struct sockaddr_in6 client_addr;
   socklen_t client_addr_len = sizeof(struct sockaddr_in6);

   // Main event loop
   while (1) {
      // If timeout, query another authority server
      if (client_info_vec_.size() &&
          time(NULL) > client_info_vec_.front().timeout_) {
         LOG << "Timeout. Deleting top authority record and querying another "
               "server." << std::endl;
         ClientInfo* client_info = &client_info_vec_.front();
         RRVec& auth_rrs = client_info->query_info_list_.back().authority_rrs_;

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
                     " not found in client info list" << std::endl;
               exit(EXIT_FAILURE);
            }

            SendQueryUpstream(client_info);
         }
      }

      // 100 ms wait for data to come in
      if (Server::HasDataToRead(sock_, 0, 100)) {
         int rlen = ReadIntoBuffer((struct sockaddr*) &client_addr, 
                                   &client_addr_len);
         DnsPacket packet(buf_);

         DnsQuery query = packet.GetQuery();

         if (packet.qr_flag()) {
            // If the packet contained an SOA, just forward it to the
            // client and delete it. Shitty, I know.
            if (CacheAllResourceRecords(packet, query)) {
               ClientInfoVec::iterator it = GetClient(packet.id());   
               if (it != client_info_vec_.end()) {
                  SendBufferToAddr(
                        (struct sockaddr*) &it->client_addr_,
                        sizeof(struct sockaddr_in6),
                        rlen);

                 RemoveClient(it);
               }
            }
         }

         if (packet.rcode() == constants::response_code::Refused) {
            // TODO respond to client
            RemoveClient(packet.id());
            continue;
         }

         // Assume that the top QueryInfo of the current ClientInfo is
         // out-of-date and be refreshed. (This is not the case when this is
         // there is no ClientInfo for this client yet (first query)).

         RRVec answer_rrs;

         ClientInfo* cur_client_info;
         ClientInfoVec::iterator it = GetClient(packet.id());

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

               SendBufferToAddr((struct sockaddr*) &client_addr,
                                sizeof(struct sockaddr_in6),
                                packet_len);

               // Go back to listening for packets
               continue;
            }

            // Cache miss and recursive-request. Initialize ClientInfo.
            LOG << "First time query after cache miss -- creating ClientInfo"
                  << std::endl;

            // Push client info to list
            client_info_vec_.push_back(
                  ClientInfo(client_addr,
                             packet.id(),
                             query,
                             authority_rrs,
                             additional_rrs));

            // Save a pointer to the client just added
            cur_client_info = &client_info_vec_.back();

            // Update timeout, which sorts the list
            if (!UpdateTimeout(packet.id())) {
               LOG << "ERROR: id " << packet.id() <<
                     " not found in client info list" << std::endl;
               exit(EXIT_FAILURE);
            }
         } else {
            // Grab a pointer to the client
            cur_client_info = &(*it);

            // Grab a pointer to the query list
            QueryInfoList& cur_query_info_list =
               cur_client_info->query_info_list_;

            // If this was a response, and there are answers to a query that
            // wasn't the original, pop its query
            if (packet.qr_flag() && cur_query_info_list.size() > 1) {
               QueryInfo& cur_query_info = cur_query_info_list.back();
               RRVec temp_answer_rrs;

               if (cache_->Get(cur_query_info.query_,
                               &temp_answer_rrs,                    // junk
                               &cur_query_info.authority_rrs_,      // junk
                               &cur_query_info.additional_rrs_)) {  // junk
                  LOG << "Intermediate query '" <<
                        cur_query_info_list.back().query_.ToString() <<
                        "' resolved. Popping from current QueryInfoList" <<
                        std::endl;
                  cur_query_info_list.pop_back();
               }
            }

            QueryInfo& cur_query_info = cur_query_info_list.back();

            RRVec& authority_rrs = cur_query_info.authority_rrs_;
            RRVec& additional_rrs = cur_query_info.additional_rrs_;

            cur_query_info.authority_rrs_.clear();
            cur_query_info.additional_rrs_.clear();

            // Cache hit -- this will be the original query, (or and SOA)
            // because if there were answers to another query (such as an A
            // record of a NS we needed), they would have been cached and then
            // the QueryInfo struct popped. The only QueryInfo struct *not*
            // popped is the original query.
            if (cache_->Get(cur_query_info.query_, &answer_rrs, &authority_rrs,
                  &additional_rrs)) {
               int packet_len = DnsPacket::ConstructPacket(buf_, packet.id(),
                     true, packet.opcode(), false, false, packet.rd_flag(),
                     true, packet.rcode(), cur_query_info_list.front().query_,
                     answer_rrs, authority_rrs, additional_rrs);

               SendBufferToAddr(
                     (struct sockaddr*) &cur_client_info->client_addr_,
                     sizeof(struct sockaddr_in6),
                     packet_len);

               // Delete the current client info
               RemoveClient(it);

               // Go back to listening for packets
               continue;
            }
         }

         QueryInfo& cur_query_info = cur_client_info->query_info_list_.back();

         // If we got a CNAME from cache, put it on the query info list
         if (answer_rrs.size()) {
            DnsQuery temp_query(answer_rrs.begin()->data(),
                                query.type(),
                                query.clz());

            LOG << "Pushing " << temp_query.ToString() <<
                  " onto current QueryInfoList" << std::endl;

            cur_client_info->query_info_list_.push_back(
                  QueryInfo(temp_query,
                            cur_query_info.authority_rrs_,
                            cur_query_info.additional_rrs_));


            // Update timeout, which sorts the list
            if (!UpdateTimeout(packet.id())) {
               LOG << "ERROR: id " << packet.id() <<
                     " not found in client info list" << std::endl;
               exit(EXIT_FAILURE);
            }
         }

         if (!SendQueryUpstream(cur_client_info))
            RemoveClient(cur_client_info->id_);
      }
   }
}

RRVec::iterator DnsServer::FindNameserverIp(DnsResourceRecord& auth_rr,
                                             RRVec& addl_rrs,
                                             bool v4) {
   RRVec::iterator it;
   uint16_t type;

   if (v4)
      type = htons(constants::type::A);
   else
      type = htons(constants::type::AAAA);

   for (it = addl_rrs.begin(); it != addl_rrs.end(); ++it) {
      if (!it->name().compare(auth_rr.data()) &&
          it->type() == type) {
         break;
      }
   }

   // Fall back to v4, if v6 miss
   if (it == addl_rrs.end() && !v4) {
      for (it = addl_rrs.begin(); it != addl_rrs.end(); ++it) {
         if (!it->name().compare(auth_rr.data()) &&
             it->type() == htons(constants::type::A)) {
            break;
         }
      }
   }

   return it;
}

bool DnsServer::SendQueryUpstream(ClientInfo* client_info) {
   // Grab the top authority from the top QueryInfo and check to see if
   // its A/AAAA record is in the additionals
   QueryInfoList& query_info_list = client_info->query_info_list_;
   if (!query_info_list.size()) {
      LOG << "Client ran out of authority RRs." << std::endl;
      return false;   
   }

   QueryInfo& query_info = query_info_list.back();
   DnsResourceRecord& auth_rr = query_info.authority_rrs_.front();
   RRVec& addl_rrs = query_info.additional_rrs_;

   RRVec::iterator it = FindNameserverIp(auth_rr, addl_rrs, 
         IN6_IS_ADDR_V4MAPPED(&client_info->client_addr_.sin6_addr));

   // If we didn't find such an A/AAAA rec, do a cache query to get the
   // right authority and A records. (kind of cheating here... :/)
   // This query may end up with missing additional information as well, in
   // which case we recurse. (This will terminate at root servers, worst case).
   if (it == addl_rrs.end()) {
      DnsQuery query2(auth_rr.data(), 
                      htons(constants::type::A), 
                      htons(constants::clz::IN));

      RRVec temp_answer_rrs;
      RRVec temp_authority_rrs;
      RRVec temp_additional_rrs;

      if (cache_->Get(query2, &temp_answer_rrs, &temp_authority_rrs,
            &temp_additional_rrs)) {
         LOG << "Probably I got an SOA for an A record of a NS. If this is the "
               "case, delete this auth and re-call this function." << std::endl;

         query_info_list.pop_back();
         return SendQueryUpstream(client_info);
      }

      LOG << "Pushing " << query2.ToString() << " onto current QueryInfoList"
            << std::endl;
      query_info_list.push_back(QueryInfo(query2,
                                          temp_authority_rrs,
                                          temp_additional_rrs));

      // Update timeout, which sorts the list
      if (!UpdateTimeout(client_info->id_)) {
         LOG << "ERROR: id " << client_info->id_ <<
               " not found in client info list" << std::endl;
         exit(EXIT_FAILURE);
      }

      return SendQueryUpstream(client_info);
   }

   // TODO i6
   struct sockaddr_in6 addr;
   addr.sin6_family = AF_INET6;
   addr.sin6_port = htons(port_);
   addr.sin6_flowinfo = 0; // what?
   addr.sin6_scope_id = 0; // what?

   if (it->type() == htons(constants::type::A)) {
      memcpy(&addr.sin6_addr,
             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF",
             12);
      memcpy(((char*) &addr.sin6_addr) + 12,
             it->data(),
             sizeof(struct in_addr));
   } else {
      memcpy(&addr.sin6_addr, it->data(), sizeof(struct in6_addr));
   }

   SendQueryUpstream((struct sockaddr*) &addr, sizeof(struct sockaddr_in6),
         query_info.query_, client_info->id_);

   return true;
}

bool DnsServer::CacheAllResourceRecords(DnsPacket& packet) {
   DnsQuery query = packet.GetQuery(); // Save query in case of SOAs
   return CacheAllResourceRecords(packet, query);
}

bool DnsServer::CacheAllResourceRecords(DnsPacket& packet, DnsQuery& query) {
   int num_rrs = packet.answer_rrs() + packet.authority_rrs() +
         packet.additional_rrs();

   bool contains_soa = false;

   for (int i = 0; i < num_rrs; ++i) {
      DnsResourceRecord record = packet.GetResourceRecord();

      if (ntohs(record.type()) == constants::type::SOA) {
         cache_->Insert(query, record);
         contains_soa = true;
      }
      else {
         cache_->Insert(record);
      }
   }

   return contains_soa;
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

   char* ip_dots_and_numbers =
      inet_ntoa(((struct sockaddr_in*) addr)->sin_addr);
   LOG << "Sent " << datalen << " bytes to " << ip_dots_and_numbers <<
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
