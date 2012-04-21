#ifndef _DNS_RESOURCE_RECORD_H
#define _DNS_RESOURCE_RECORD_H

#include <stdint.h>

#include <string>

class DnsResourceRecord {
  public:
   DnsResourceRecord(DnsPacket& packet);
   virtual ~DnsResourceRecord();

   void Print();
   void PrintData(int cutoff);

   // Getters
   std::string name() { return name_; }
   uint16_t type() { return type_; }
   uint16_t clz() { return clz_; }
   uint32_t ttl() { return ttl_; }
   uint16_t data_len() { return data_len_; }
   char* data() { return data_; }

  private:
   std::string name_;
   uint16_t type_;
   uint16_t clz_;
   uint32_t ttl_;
   uint16_t data_len_;
   char* data_;
};

#endif   // _DNS_RESOURCE_RECORD_H_
