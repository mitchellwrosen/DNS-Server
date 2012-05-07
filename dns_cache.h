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

#include <list>
#include <map>
#include <utility>
#include <vector>

#include "smartalloc.h"

#include "dns_packet.h"

typedef std::pair<time_t, DnsResourceRecord> TimestampedRR;

typedef std::vector<TimestampedRR, STLsmartalloc<TimestampedRR> > TimestampedRRVec;

typedef std::map<DnsQuery, TimestampedRRVec, std::less<DnsQuery>, STLsmartalloc<std::pair<DnsQuery, TimestampedRRVec> > > Cache;

class DnsCache {
  public:
   DnsCache();

   // Gets the best match the cache contains. Has 3 out-parameters.
   // Constructs a DnsQuery with the given three fields. Requires network
   // byte order.
   bool Get(std::string name,
            uint16_t type,
            uint16_t clz,
            RRList* answer_rrs,
            RRList* authority_rrs,
            RRList* additional_rrs);

   bool Get(DnsQuery& query,
            RRList* answer_rrs,
            RRList* authority_rrs,
            RRList* additional_rrs);

   // Queries the cache for an exact match. Returns true if such a match is
   // found, false otherwise. Constructs a DnsQuery with the given fields. Has
   // one out-parameter. Requires network byte order.
   bool GetIterative(std::string name,
                     uint16_t type,
                     uint16_t clz,
                     RRList* rrs,
                     Cache& cache);

   bool GetIterative(DnsQuery& query,
                     RRList* rrs,
                     Cache& cache);

   // Recursively queries the cache for NS records. NS record isn't hard-coded
   // into the function, but it's the only RR that makes any sense to perform
   // this kind of recursion on. Has 1 out-parameter. Requires network byte
   // order.
   void GetRecursive(std::string name,
                     uint16_t type,
                     uint16_t clz,
                     RRList* rrs,
                     Cache& cache);

   void GetRecursive(DnsQuery& query,
                     RRList* rrs,
                     Cache& cache);

   // Timestamps and insertsthe resource records into the cache with key
   // |query|.
   void Insert(DnsQuery& query,
               RRList* resource_records);
   void Insert(DnsQuery& query, const DnsResourceRecord& resource_record);
   void Insert(const DnsResourceRecord& resource_record);

  private:
   Cache cache_;
   Cache ncache_; // Negative cache for SOAs
};

#endif   // _DNS_CACHE_H_
