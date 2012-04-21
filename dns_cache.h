#ifndef _DNS_CACHE_H_
#define _DNS_CACHE_H_

#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <map>
#include <utility>
#include <vector>

#include "smartalloc.h"

#include "dns_packet.h"
#include "dns_query.h"
#include "dns_resource_record.h"

class DnsCache {
  public:
   DnsCache();

   // Gets the best match the cache contains. Has 3 out-parameters.
   // Constructs a DnsQuery with the given three fields. Requires network
   // byte order.
   bool Get(std::string name,
            uint16_t type,
            uint16_t clz,
            std::vector<DnsResourceRecord>* answer_rrs,
            std::vector<DnsResourceRecord>* authority_rrs,
            std::vector<DnsResourceRecord>* additional_rrs);

   bool Get(DnsQuery& query, 
            std::vector<DnsResourceRecord>* answer_rrs,
            std::vector<DnsResourceRecord>* authority_rrs,
            std::vector<DnsResourceRecord>* additional_rrs);

   // Queries the cache for an exact match. Returns true if such a match is
   // found, false otherwise. Constructs a DnsQuery with the given fields. Has 
   // one out-parameter. Requires network byte order.
   bool GetIterative(std::string name,
                     uint16_t type,
                     uint16_t clz,
                     std::vector<DnsResourceRecord>* rrs);

   bool GetIterative(DnsQuery& query, 
                     std::vector<DnsResourceRecord>* rrs);

   // Recursively queries the cache for NS records. NS record isn't hard-coded
   // into the function, but it's the only RR that makes any sense to perform
   // this kind of recursion on. Has 1 out-parameter. Requires network byte
   // order.
   void GetRecursive(std::string name,
                     uint16_t type,
                     uint16_t clz,
                     std::vector<DnsResourceRecord>* rrs);

   void GetRecursive(DnsQuery& query, 
                     std::vector<DnsResourceRecord>* rrs);


   // Timestamps and insertsthe resource records into the cache with key 
   // |query|.
   void Insert(DnsQuery query, 
               std::vector<DnsResourceRecord> resource_records);

   typedef std::pair<time_t, DnsResourceRecord> TimestampedDnsResourceRecord;
   typedef std::map<DnsQuery, std::vector<TimestampedDnsResourceRecord> > Cache;
  
  private:

   Cache cache_;
};

#endif   // _DNS_CACHE_H_
