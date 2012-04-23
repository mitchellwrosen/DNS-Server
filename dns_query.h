#ifndef _DNS_QUERY_H_
#define _DNS_QUERY_H_

#include <stdint.h>

#include <string>

class DnsPacket;

class DnsQuery {
  public:
   DnsQuery(DnsPacket& data);
   DnsQuery(std::string name, int type, int clz);

   bool operator<(const DnsQuery& query) const;

   // "Construct" a query at |p|.
   char* Construct(char* p);
   void Print();

   // Getters
   std::string name() { return name_; }
   uint16_t type() { return type_; }
   uint16_t clz() { return clz_; }

  private:
   std::string name_;
   uint16_t type_;
   uint16_t clz_;
};

#endif   // _DNS_QUERY_H_
