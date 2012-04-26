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

#include <map>
#include <utility>
#include <set>

#include "smartalloc.h"

#include "debug.h"

#include "dns_cache.h"
#include "dns_packet.h"
#include "dns_query.h"
#include "dns_resource_record.h"

namespace constants = dns_packet_constants;

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
                   std::set<DnsResourceRecord>* answer_rrs,
                   std::set<DnsResourceRecord>* authority_rrs,
                   std::set<DnsResourceRecord>* additional_rrs) {
   DnsQuery query(name, type, clz);
   return Get(query, answer_rrs, authority_rrs, additional_rrs);
}

bool DnsCache::Get(DnsQuery& query,
                   std::set<DnsResourceRecord>* answer_rrs,
                   std::set<DnsResourceRecord>* authority_rrs,
                   std::set<DnsResourceRecord>* additional_rrs) {
   // Look for exact match
   if (GetIterative(query, answer_rrs))
      return true;

   std::set<DnsResourceRecord>::iterator it;

   // Look for CNAME match, only if it's not one of a few specific RRs
   uint16_t type = ntohs(query.type());
   if (type != constants::type::NS &&
       type != constants::type::MX &&
       type != constants::type::CNAME) { // TODO there are more!
      if (GetIterative(query.name(),
                       ntohs(constants::type::CNAME),
                       query.clz(),
                       answer_rrs)) {
         bool found = false;

         // We hit a CNAME - try to fill our answer with the query type,
         // and authority with NSs.
         // If we find an A record for this CNAME, consider it a cache
         // hit. Otherwise, if we're just going to return a CNAME,
         // consider it a cache miss
         if (GetIterative(answer_rrs->begin()->data(),
                          query.type(),
                          query.clz(),
                          answer_rrs))
            found = true;

         GetRecursive(it->data(),
                      ntohs(constants::type::NS),
                      query.clz(),
                      authority_rrs);

         // Try to fill out additional with A records of NS
         for (it = authority_rrs->begin(); it != authority_rrs->end(); ++it)
            GetIterative(it->data(),
                         ntohs(constants::type::A),
                         query.clz(),
                         additional_rrs);

         // If we hit any A records for any CNAMEs, cache hit. Otherwise,
         // cache miss.
         return found;
      }
   }

   // No record or CNAME found - recurse up looking for name servers
   GetRecursive(query.name(),
                ntohs(constants::type::NS),
                query.clz(),
                authority_rrs);

   // Try to fill out additional information with A records of NS
   for (it = authority_rrs->begin(); it != authority_rrs->end(); ++it) {
      GetIterative(it->data(),
                   ntohs(constants::type::A),
                   query.clz(),
                   additional_rrs);
   }

   return false;
}

bool DnsCache::GetIterative(std::string name,
                            uint16_t type,
                            uint16_t clz,
                            std::set<DnsResourceRecord>* rrs) {
   DnsQuery query(name, type, clz);
   return GetIterative(query, rrs);
}

bool DnsCache::GetIterative(DnsQuery& query,
                            std::set<DnsResourceRecord>* rrs) {
   LOG << "Looking for " << query.ToString();
   Cache::iterator it = cache_.find(query);
   if (it != cache_.end()) {
      time_t now = time(NULL);

      std::set<TimestampedDnsResourceRecord>::iterator it2;
      for (it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
         // TODO Remove all expired records
         // Check every returned RR is not expired (ignore TTL == 0)
         if (ntohl(it2->second.ttl()) &&
             now - it2->first > (time_t) ntohl(it2->second.ttl())) {
            // TODO Remove
            LOG << "-- NOT FOUND" << std::endl;
            return false;
         }
      }

      // Push all RRs to the supplied set
      LOG << "-- FOUND" << std::endl;
      for (it2 = it->second.begin(); it2 != it->second.end(); ++it2)
         rrs->insert(it2->second);

      return true;
   }

   // No hits
   LOG << "-- NOT FOUND" << std::endl;
   return false;
}

void DnsCache::GetRecursive(std::string name,
                            uint16_t type,
                            uint16_t clz,
                            std::set<DnsResourceRecord>* rrs) {
   DnsQuery query(name, type, clz);
   GetRecursive(query, rrs);
}


void DnsCache::GetRecursive(DnsQuery& query,
                            std::set<DnsResourceRecord>* rrs) {
   if (GetIterative(query, rrs))
      return;

   GetRecursive(DnsPacket::ShortenName(query.name()),
                query.type(),
                query.clz(),
                rrs);
}

void DnsCache::Insert(DnsQuery& query,
                      std::set<DnsResourceRecord>* resource_records) {
   std::set<DnsResourceRecord>::iterator it;
   for (it = resource_records->begin(); it != resource_records->end(); ++it)
      Insert(query, *it);
}

void DnsCache::Insert(DnsQuery& query,
                      const DnsResourceRecord& resource_record) {
   Cache::iterator it = cache_.find(query);
   if (it == cache_.end()) {
      LOG << "Query " << query.ToString() << " not found in cache -- inserting "
            << resource_record.ToString() << std::endl;
      std::set<TimestampedDnsResourceRecord> timestamped_resource_records;
      timestamped_resource_records.insert(
            TimestampedDnsResourceRecord(time(NULL), resource_record));
      cache_.insert(
            std::pair<DnsQuery, std::set<TimestampedDnsResourceRecord> >
                  (query, timestamped_resource_records));
   } else {
      LOG << "Query " << query.ToString() <<
            " found in cache -- adding " << resource_record.ToString() <<
            " to set" << std::endl;
      it->second.insert(TimestampedDnsResourceRecord(
            time(NULL), resource_record));
   }
}

void DnsCache::Insert(const DnsResourceRecord& resource_record) {
   DnsQuery query = resource_record.ConstructQuery();
   Insert(query, resource_record);
}
