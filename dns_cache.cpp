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

namespace dns_packet_constants = constants;

DnsCache::DnsCache() {
   // inialize with root servers
}

void DnsCache::Get(std::string& name,
                   int type,
                   int clz,
                   std::vector<DnsResourceRecord>* answer_rrs,
                   std::vector<DnsResourceRecord>* authority_rrs,
                   std::vector<DnsResourceRecord>* additional_rrs) {
   DnsQuery query(name, type, clz);
   Get(query, answer_rrs, authority_rrs, additional_rrs);
}

void DnsCache::Get(DnsQuery& query,
                   std::vector<DnsResourceRecord>* answer_rrs,
                   std::vector<DnsResourceRecord>* authority_rrs,
                   std::vector<DnsResourceRecord>* additional_rrs) {
   // Look for exact match
   if (GetIterative(query, answer_rrs))
      return true;

   // Look for CNAME match
   switch (query.type()) {
      case constants::type::NS:
      case constants::type::MX:
      case constants::type::CNAME:
      // ... others ...
         break;
      default:
         if (GetIterative(query.name(), 
                          constants::type::CNAME, 
                          query.clz(), 
                          answer_rrs)) {
            // We hit one or more CNAMEs - try to fill our answer with the 
            // query type, and authority with NSs
            std::vector<DnsResourceRecord>::iterator it;
            for (it = answer_rrs->begin(); it != answer_rrs->end(); ++it) {
               GetIterative(it->data(), query.type(), query.clz(), answer_rrs);
               GetRecursive(it->data(), 
                            constants::type::NS, 
                            query.clz(),
                            authority_rrs);
            }

            // Try to fill out additional with A records of NS
            for (it = authority_rrs->begin(); it != authority_rrs->end(); ++i)
               GetIterative(it->data(), 
                            constants::type::A, 
                            query.clz(), 
                            additional_rrs); 

            // No matter what, we hit one or more CNAMEs, so return true (the
            // server may then have to make an additional query to resolve the
            // query type, if only CNAMEs were found)
            return true;
         }
   }

   // No record or CNAME found - recurse up looking for name servers
   GetRecursive(query.name(), constants::type::NS, query.clz(), authority_rrs);
}

bool DnsCache::GetIterative(std::string& name,
                            int type,
                            int clz,
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

void DnsCache::GetRecursive(std::string& name,
                            int type,
                            int clz,
                            std::vector<DnsResourceRecord>* rrs) {
   DnsQuery query(name, type, clz);
   GetRecursive(query, rrs);
}


void DnsCache::GetRecursive(DnsQuery& query, 
                            std::vector<DnsResourceRecord>* rrs) {
   if (GetIterative(query, rrs))
      return true;

   GetRecursive(DnsPacket::ShortenName(query.name()), 
                query.type(),
                query.clz());
}
