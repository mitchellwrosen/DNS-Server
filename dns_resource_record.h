#ifndef _DNS_RESOURCE_RECORD_H
#define _DNS_RESOURCE_RECORD_H

#include <stdint.h>

#include <string>

#include "dns_query.h"

class DnsPacket;

class DnsResourceRecord {
  public:
   DnsResourceRecord(DnsPacket& packet);
   DnsResourceRecord(std::string name_, uint16_t type, uint16_t clz,
         uint32_t ttl, uint16_t data_len_, char* data);
   DnsResourceRecord(const DnsResourceRecord& rr);
   virtual ~DnsResourceRecord();

   bool operator<(const DnsResourceRecord& query) const;

   DnsQuery ConstructQuery() const;

   void Print();
   void PrintData(int cutoff);

   // Getters
   std::string name() const { return name_; }
   uint16_t type() const { return type_; }
   uint16_t clz() const { return clz_; }
   uint32_t ttl() const { return ttl_; }
   uint16_t data_len() const { return data_len_; }
   char* data() const { return data_; }

  private:
   std::string name_;
   uint16_t type_;
   uint16_t clz_;
   uint32_t ttl_;
   uint16_t data_len_;
   char* data_;
};

#endif   // _DNS_RESOURCE_RECORD_H_
