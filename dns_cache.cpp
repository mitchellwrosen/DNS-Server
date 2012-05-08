#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <list>
#include <map>
#include <utility>
#include <vector>

#include "checksum.h"
#include "smartalloc.h"

#include "debug.h"

#include "dns_cache.h"
#include "dns_packet.h"

namespace constants = dns_packet_constants;

namespace dns_cache {
const int kCache = 0;
const int kNegativeCache = 1;
}

DnsCache::DnsCache() {
   char a[] = "\x01\x61\x0c\x72\x6f\x6f\x74\x2d\x73\x65\x72\x76\x65\x72\x73\x03\x6e\x65\x74";
   char b[] = "\x01\x62\x0c\x72\x6f\x6f\x74\x2d\x73\x65\x72\x76\x65\x72\x73\x03\x6e\x65\x74";
   char c[] = "\x01\x63\x0c\x72\x6f\x6f\x74\x2d\x73\x65\x72\x76\x65\x72\x73\x03\x6e\x65\x74";
   char d[] = "\x01\x64\x0c\x72\x6f\x6f\x74\x2d\x73\x65\x72\x76\x65\x72\x73\x03\x6e\x65\x74";
   char e[] = "\x01\x65\x0c\x72\x6f\x6f\x74\x2d\x73\x65\x72\x76\x65\x72\x73\x03\x6e\x65\x74";
   char f[] = "\x01\x66\x0c\x72\x6f\x6f\x74\x2d\x73\x65\x72\x76\x65\x72\x73\x03\x6e\x65\x74";
   char g[] = "\x01\x67\x0c\x72\x6f\x6f\x74\x2d\x73\x65\x72\x76\x65\x72\x73\x03\x6e\x65\x74";
   char h[] = "\x01\x68\x0c\x72\x6f\x6f\x74\x2d\x73\x65\x72\x76\x65\x72\x73\x03\x6e\x65\x74";
   char i[] = "\x01\x69\x0c\x72\x6f\x6f\x74\x2d\x73\x65\x72\x76\x65\x72\x73\x03\x6e\x65\x74";
   char j[] = "\x01\x6a\x0c\x72\x6f\x6f\x74\x2d\x73\x65\x72\x76\x65\x72\x73\x03\x6e\x65\x74";
   char k[] = "\x01\x6b\x0c\x72\x6f\x6f\x74\x2d\x73\x65\x72\x76\x65\x72\x73\x03\x6e\x65\x74";
   char l[] = "\x01\x6c\x0c\x72\x6f\x6f\x74\x2d\x73\x65\x72\x76\x65\x72\x73\x03\x6e\x65\x74";
   char m[] = "\x01\x6d\x0c\x72\x6f\x6f\x74\x2d\x73\x65\x72\x76\x65\x72\x73\x03\x6e\x65\x74";

   char a_ip[] = "\xc6\x29\x00\x04";
   char b_ip[] = "\xc0\xe4\x4f\xc9";
   char c_ip[] = "\xc0\x21\x04\x0c";
   char d_ip[] = "\x80\x08\x0a\x5a";
   char e_ip[] = "\xc0\xcb\xe6\x0a";
   char f_ip[] = "\xc0\x05\x05\xf1";
   char g_ip[] = "\xc0\x70\x24\x04";
   char h_ip[] = "\x80\x3f\x02\x35";
   char i_ip[] = "\xc0\x24\x94\x11";
   char j_ip[] = "\x81\x3a\x80\x1e";
   char k_ip[] = "\xc1\x00\x0e\x81";
   char l_ip[] = "\xc7\x07\x53\x2a";
   char m_ip[] = "\xca\x0c\x1b\x21";

   // Initialize with root servers -- match with queries for ""
   DnsQuery query = DnsQuery("",
                             htons(constants::type::NS),
                             htons(constants::clz::IN));

   DnsResourceRecord rr_a("", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(a)+1), a);
   DnsResourceRecord rr_b("", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(b)+1), b);
   DnsResourceRecord rr_c("", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(c)+1), c);
   DnsResourceRecord rr_d("", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(d)+1), d);
   DnsResourceRecord rr_e("", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(e)+1), e);
   DnsResourceRecord rr_f("", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(f)+1), f);
   DnsResourceRecord rr_g("", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(g)+1), g);
   DnsResourceRecord rr_h("", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(h)+1), h);
   DnsResourceRecord rr_i("", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(i)+1), i);
   DnsResourceRecord rr_j("", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(j)+1), j);
   DnsResourceRecord rr_k("", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(k)+1), k);
   DnsResourceRecord rr_l("", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(l)+1), l);
   DnsResourceRecord rr_m("", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(m)+1), m);

   DnsResourceRecord rr_a_ip(a, htons(constants::type::A),
         htons(constants::clz::IN), 0, htons(4), a_ip);
   DnsResourceRecord rr_b_ip(b, htons(constants::type::A),
         htons(constants::clz::IN), 0, htons(4), b_ip);
   DnsResourceRecord rr_c_ip(c, htons(constants::type::A),
         htons(constants::clz::IN), 0, htons(4), c_ip);
   DnsResourceRecord rr_d_ip(d, htons(constants::type::A),
         htons(constants::clz::IN), 0, htons(4), d_ip);
   DnsResourceRecord rr_e_ip(e, htons(constants::type::A),
         htons(constants::clz::IN), 0, htons(4), e_ip);
   DnsResourceRecord rr_f_ip(f, htons(constants::type::A),
         htons(constants::clz::IN), 0, htons(4), f_ip);
   DnsResourceRecord rr_g_ip(g, htons(constants::type::A),
         htons(constants::clz::IN), 0, htons(4), g_ip);
   DnsResourceRecord rr_h_ip(h, htons(constants::type::A),
         htons(constants::clz::IN), 0, htons(4), h_ip);
   DnsResourceRecord rr_i_ip(i, htons(constants::type::A),
         htons(constants::clz::IN), 0, htons(4), i_ip);
   DnsResourceRecord rr_j_ip(j, htons(constants::type::A),
         htons(constants::clz::IN), 0, htons(4), j_ip);
   DnsResourceRecord rr_k_ip(k, htons(constants::type::A),
         htons(constants::clz::IN), 0, htons(4), k_ip);
   DnsResourceRecord rr_l_ip(l, htons(constants::type::A),
         htons(constants::clz::IN), 0, htons(4), l_ip);
   DnsResourceRecord rr_m_ip(m, htons(constants::type::A),
         htons(constants::clz::IN), 0, htons(4), m_ip);

   Insert(query, rr_a);
   Insert(query, rr_b);
   Insert(query, rr_c);
   Insert(query, rr_d);
   Insert(query, rr_e);
   Insert(query, rr_f);
   Insert(query, rr_g);
   Insert(query, rr_h);
   Insert(query, rr_i);
   Insert(query, rr_j);
   Insert(query, rr_k);
   Insert(query, rr_l);
   Insert(query, rr_m);

   Insert(rr_a_ip);
   Insert(rr_b_ip);
   Insert(rr_c_ip);
   Insert(rr_d_ip);
   Insert(rr_e_ip);
   Insert(rr_f_ip);
   Insert(rr_g_ip);
   Insert(rr_h_ip);
   Insert(rr_i_ip);
   Insert(rr_j_ip);
   Insert(rr_k_ip);
   Insert(rr_l_ip);
   Insert(rr_m_ip);
}

bool DnsCache::Get(std::string name,
                   uint16_t type,
                   uint16_t clz,
                   RRVec* answer_rrs,
                   RRVec* authority_rrs,
                   RRVec* additional_rrs) {
   DnsQuery query(name, type, clz);
   return Get(query, answer_rrs, authority_rrs, additional_rrs);
}

bool DnsCache::Get(DnsQuery& query,
                   RRVec* answer_rrs,
                   RRVec* authority_rrs,
                   RRVec* additional_rrs) {
   bool ret = Get2(query, answer_rrs, authority_rrs, additional_rrs);

   // Randomize authorities
   std::random_shuffle(authority_rrs->begin(), authority_rrs->end());

   return ret;
}

bool DnsCache::Get2(DnsQuery& query,
                    RRVec* answer_rrs,
                    RRVec* authority_rrs,
                    RRVec* additional_rrs) {
   // First and foremost, search the negative cache
   if (GetIterative(query, authority_rrs, ncache_))
      return true;

   // Look for exact match
   if (GetIterative(query, answer_rrs, cache_)) {
      // Fill authority section
      GetRecursive(query.name(),
                   ntohs(constants::type::NS),
                   query.clz(),
                   authority_rrs,
                   cache_);

      // If NS or MX, try to fill additional with A/AAAA
      uint16_t type = ntohs(query.type());
      RRVec::iterator it;
      if (type == constants::type::NS) {
         for (it = answer_rrs->begin(); it != answer_rrs->end(); ++it) {
            GetIterative(it->data(),
                         ntohs(constants::type::A),
                         query.clz(),
                         additional_rrs,
                         cache_);

            GetIterative(it->data(),
                         ntohs(constants::type::AAAA),
                         query.clz(),
                         additional_rrs,
                         cache_);
         }
      } else if (type == constants::type::MX) {
         for (it = answer_rrs->begin(); it != answer_rrs->end(); ++it) {
            GetIterative(it->data() + 2,
                         ntohs(constants::type::A),
                         query.clz(),
                         additional_rrs,
                         cache_);

            GetIterative(it->data() + 2,
                         ntohs(constants::type::AAAA),
                         query.clz(),
                         additional_rrs,
                         cache_);
         }
      }

      return true;
   }

   RRVec::iterator it;

   // Look for CNAME match
   if (GetIterative(query.name(),
                    ntohs(constants::type::CNAME),
                    query.clz(),
                    answer_rrs,
                    cache_)) {
      bool found = false;

      // Follow CNAME chains, break on query.type() found, or no more CNAMEs
      while (1) {
         if (GetIterative(answer_rrs->back().data(),
                          query.type(),
                          query.clz(),
                          answer_rrs,
                          cache_)) {
            found = true;
            break;
         }

         if (!GetIterative(answer_rrs->back().data(),
                           ntohs(constants::type::CNAME),
                           query.clz(),
                           answer_rrs,
                           cache_)) {
            break;
         }
      }

      // If no record was found, report back to the server only the last CNAME
      if (!found) {
         while (answer_rrs->size() > 1)
            answer_rrs->erase(answer_rrs->begin());

         // Try to fill out authority with NS of the last CNAME
         GetRecursive(answer_rrs->back().data(),
                      ntohs(constants::type::NS),
                      query.clz(),
                      authority_rrs,
                      cache_);
      } else {
         // Try to fill out authority with NS of the answer
         GetRecursive(answer_rrs->back().name(),
                      ntohs(constants::type::NS),
                      query.clz(),
                      authority_rrs,
                      cache_);
      }

      // Try to fill out additional with A/AAAA records of NS
      for (it = authority_rrs->begin(); it != authority_rrs->end(); ++it) {
         GetIterative(it->data(),
                      ntohs(constants::type::A),
                      query.clz(),
                      additional_rrs,
                      cache_);

         GetIterative(it->data(),
                      ntohs(constants::type::AAAA),
                      query.clz(),
                      additional_rrs,
                      cache_);
      }

      // If we hit any A/AAAA records for any CNAMEs, cache hit. Otherwise,
      // cache miss.
      return found;
   }

   // No record or CNAME found - recurse up looking for name servers
   GetRecursive(query.name(),
                ntohs(constants::type::NS),
                query.clz(),
                authority_rrs,
                cache_);

   // Try to fill out additional information with A/AAAA records of NS
   for (it = authority_rrs->begin(); it != authority_rrs->end(); ++it) {
      GetIterative(it->data(),
                   ntohs(constants::type::A),
                   query.clz(),
                   additional_rrs,
                   cache_);

      GetIterative(it->data(),
                   ntohs(constants::type::AAAA),
                   query.clz(),
                   additional_rrs,
                   cache_);
   }

   return false;
}

bool DnsCache::GetIterative(std::string name,
                            uint16_t type,
                            uint16_t clz,
                            RRVec* rrs,
                            Cache& cache) {
   DnsQuery query(name, type, clz);
   return GetIterative(query, rrs, cache);
}

bool DnsCache::GetIterative(DnsQuery& query,
                            RRVec* rrs,
                            Cache& cache) {
   LOG << "Looking for " << query.ToString();
   if (&cache == &ncache_)
      LOG << " in negative cache";

   Cache::iterator it = cache.find(query);
   if (it != cache.end()) {
      time_t now = time(NULL);

      TimestampedRRVec::iterator it2;
      for (it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
         // ignore TTL == 0
         if (ntohl(it2->second.ttl())) {
            // Remove expired RRs
            if (now - it2->first > (time_t) ntohl(it2->second.ttl())) {
               LOG << "Erasing expired record" << std::endl;
               it2 = it->second.erase(it2);
               it2--;
            }

            // Not expired -- update TTL
            else {
               //LOG << "Updating TTL: Subtracting " << now - it2->first <<
               //      std::endl;
               it2->second.SubtractFromTtl(now - it2->first);
               it2->first = now;
            }
         }
      }

      // If we removed them all due to expired TTLs, return false (cache miss)
      if (!it->second.size()) {
         LOG << " -- NOT FOUND" << std::endl;
         return false;
      }

      // Push all RRs to the supplied vector
      LOG << "-- FOUND" << std::endl;
      for (it2 = it->second.begin(); it2 != it->second.end(); ++it2)
         rrs->push_back(it2->second);

      return true;
   }

   // No hits
   LOG << "-- NOT FOUND" << std::endl;
   return false;
}

void DnsCache::GetRecursive(std::string name,
                            uint16_t type,
                            uint16_t clz,
                            RRVec* rrs,
                            Cache& cache) {
   DnsQuery query(name, type, clz);
   GetRecursive(query, rrs, cache);
}


void DnsCache::GetRecursive(DnsQuery& query,
                            RRVec* rrs,
                            Cache& cache) {
   if (GetIterative(query, rrs, cache))
      return;

   GetRecursive(DnsPacket::ShortenName(query.name()),
                query.type(),
                query.clz(),
                rrs,
                cache);
}

void DnsCache::Insert(DnsQuery& query,
                      const DnsResourceRecord& resource_record) {
   Cache* cache;
   if (ntohs(resource_record.type()) == constants::type::SOA)
      cache = &ncache_;
   else
      cache = &cache_;

   Cache::iterator it = cache->find(query);
   if (it == cache->end()) {
      LOG << "Query " << query.ToString() << " not found in cache -- inserting "
            << resource_record.ToString() << std::endl;
      TimestampedRRVec timestamped_resource_records;
      timestamped_resource_records.push_back(
            TimestampedRR(time(NULL), resource_record));
      cache->insert(
            std::pair<DnsQuery, TimestampedRRVec >
                  (query, timestamped_resource_records));
   } else {
      LOG << "Query " << query.ToString() <<
            " found in cache -- adding " << resource_record.ToString() <<
            " to vector" << std::endl;
      TimestampedRRVec::iterator it2;
      for (it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
         if (resource_record == it2->second) {
            LOG << " -- actually not adding (duplicate)" << std::endl;
            break;
         }
      }

      // Only insert if we didn't find the resource record already in the vec
      if (it2 == it->second.end())
         it->second.push_back(TimestampedRR(
               time(NULL), resource_record));
   }
}

void DnsCache::Insert(const DnsResourceRecord& resource_record) {
   if (ntohs(resource_record.type()) == constants::type::SOA)
      LOG << "WARNING: Inserting an SOA with no Query. Generating a Query from "
            " the Resource Record." << std::endl;
   DnsQuery query = resource_record.ConstructQuery();
   Insert(query, resource_record);
}
