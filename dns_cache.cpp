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
#include <vector>

#include "smartalloc.h"

#include "dns_cache.h"
#include "dns_packet.h"
#include "dns_query.h"
#include "dns_resource_record.h"

namespace constants = dns_packet_constants;

DnsCache::DnsCache() {
   // inialize with root servers
}

bool DnsCache::Get(std::string name,
                   uint16_t type,
                   uint16_t clz,
                   std::vector<DnsResourceRecord>* answer_rrs,
                   std::vector<DnsResourceRecord>* authority_rrs,
                   std::vector<DnsResourceRecord>* additional_rrs) {
   DnsQuery query(name, type, clz);
   return Get(query, answer_rrs, authority_rrs, additional_rrs);
}

bool DnsCache::Get(DnsQuery& query,
                   std::vector<DnsResourceRecord>* answer_rrs,
                   std::vector<DnsResourceRecord>* authority_rrs,
                   std::vector<DnsResourceRecord>* additional_rrs) {
   // Look for exact match
   if (GetIterative(query, answer_rrs))
      return true;

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

         // We hit one or more CNAMEs - try to fill our answer with the 
         // query type, and authority with NSs
         std::vector<DnsResourceRecord>::iterator it;
         for (it = answer_rrs->begin(); it != answer_rrs->end(); ++it) {
            // If we find an A record for this CNAME, consider it a cache
            // hit. Otherwise, if we're just going to return a CNAME,
            // consider it a cache miss 
            if (GetIterative(it->data(), 
                             query.type(), 
                             query.clz(), 
                             answer_rrs))
               found = true;
            GetRecursive(it->data(), 
                         ntohs(constants::type::NS), 
                         query.clz(),
                         authority_rrs);
         }

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
   return false;
}

bool DnsCache::GetIterative(std::string name,
                            uint16_t type,
                            uint16_t clz,
                            std::vector<DnsResourceRecord>* rrs) {
   DnsQuery query(name, type, clz);
   return GetIterative(query, rrs);
}

bool DnsCache::GetIterative(DnsQuery& query, 
                            std::vector<DnsResourceRecord>* rrs) {
   Cache::iterator it = cache_.find(query);
   if (it != cache_.end()) {
      time_t now = time(NULL);

      std::vector<TimestampedDnsResourceRecord>::iterator it2;
      for (it2 = it->second.begin(); it2 != it->second.end(); ++it2)
         // Check every returned RR is not expired (ignore TTL == 0)
         if (it2->first && now - it2->first > it2->second.ttl())  
            return false;

      // Push all RRs to the supplied vector
      for (it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
         rrs->push_back(it2->second);
         return true;
      }
   }

   // No hits
   return false;
}

void DnsCache::GetRecursive(std::string name,
                            uint16_t type,
                            uint16_t clz,
                            std::vector<DnsResourceRecord>* rrs) {
   DnsQuery query(name, type, clz);
   GetRecursive(query, rrs);
}


void DnsCache::GetRecursive(DnsQuery& query, 
                            std::vector<DnsResourceRecord>* rrs) {
   if (GetIterative(query, rrs))
      return;

   GetRecursive(DnsPacket::ShortenName(query.name()), 
                query.type(),
                query.clz(),
                rrs);
}
