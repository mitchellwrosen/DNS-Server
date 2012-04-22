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
   char a[] = "a.root-servers.net.";
   char b[] = "b.root-servers.net.";
   char c[] = "c.root-servers.net.";
   char d[] = "d.root-servers.net.";
   char e[] = "e.root-servers.net.";
   char f[] = "f.root-servers.net.";
   char g[] = "g.root-servers.net.";
   char h[] = "h.root-servers.net.";
   char i[] = "i.root-servers.net.";
   char j[] = "j.root-servers.net.";
   char k[] = "k.root-servers.net.";
   char l[] = "l.root-servers.net.";
   char m[] = "m.root-servers.net.";

   // Initialize with root servers -- match with queries for ""
   DnsQuery query = DnsQuery("",
                             htons(constants::type::NS),
                             htons(constants::clz::IN));

   std::set<DnsResourceRecord> root_servers;
   root_servers.insert(DnsResourceRecord(".", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(a)+1), a)); //TODO +1? or no?
   root_servers.insert(DnsResourceRecord(".", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(b)+1), b));
   root_servers.insert(DnsResourceRecord(".", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(c)+1), c));
   root_servers.insert(DnsResourceRecord(".", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(d)+1), d));
   root_servers.insert(DnsResourceRecord(".", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(e)+1), e));
   root_servers.insert(DnsResourceRecord(".", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(f)+1), f));
   root_servers.insert(DnsResourceRecord(".", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(g)+1), g));
   root_servers.insert(DnsResourceRecord(".", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(h)+1), h));
   root_servers.insert(DnsResourceRecord(".", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(i)+1), i));
   root_servers.insert(DnsResourceRecord(".", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(j)+1), j));
   root_servers.insert(DnsResourceRecord(".", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(k)+1), k));
   root_servers.insert(DnsResourceRecord(".", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(l)+1), l));
   root_servers.insert(DnsResourceRecord(".", htons(constants::type::NS),
         htons(constants::clz::IN), 0, htons(strlen(m)+1), m));

   // TODO root servers' IPs

   Insert(query, &root_servers);
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
         std::set<DnsResourceRecord>::iterator it;
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
                            std::set<DnsResourceRecord>* rrs) {
   DnsQuery query(name, type, clz);
   return GetIterative(query, rrs);
}

bool DnsCache::GetIterative(DnsQuery& query,
                            std::set<DnsResourceRecord>* rrs) {
   LOG << "Looking for exact match (" << query.name() << ", " <<
         ntohs(query.type()) << ", " << ntohs(query.clz()) << ") ";
   Cache::iterator it = cache_.find(query);
   if (it != cache_.end()) {
      time_t now = time(NULL);

      std::set<TimestampedDnsResourceRecord>::iterator it2;
      for (it2 = it->second.begin(); it2 != it->second.end(); ++it2)
         // Check every returned RR is not expired (ignore TTL == 0)
         if (ntohl(it2->second.ttl()) &&
             now - it2->first > (time_t) ntohl(it2->second.ttl())) {
            LOG << "-- NOT FOUND" << std::endl;
            return false;
         }

      // Push all RRs to the supplied set
      for (it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
         rrs->insert(it2->second);
         LOG << "-- FOUND" << std::endl;
         return true;
      }
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
      LOG << "Query not found in cache -- inserting" << std::endl;
      std::set<TimestampedDnsResourceRecord> timestamped_resource_records;
      timestamped_resource_records.insert(
            TimestampedDnsResourceRecord(time(NULL), resource_record));
      cache_.insert(
            std::pair<DnsQuery, std::set<TimestampedDnsResourceRecord> >
                  (query, timestamped_resource_records));
   } else {
      LOG << "Query found in cache -- adding resource record to set";
      it->second.insert(TimestampedDnsResourceRecord(
            time(NULL), resource_record));
   }
}

void DnsCache::Insert(const DnsResourceRecord& resource_record) {
   DnsQuery query = resource_record.ConstructQuery();
   Insert(query, resource_record);
}
