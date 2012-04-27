#ifndef _DNS_QUERY_H_
#define _DNS_QUERY_H_

#include <stdint.h>

#include <map>
#include <string>

class DnsPacket;

class DnsQuery {
  public:
   DnsQuery(DnsPacket& data);

   // Requires network-order parameters
   DnsQuery(std::string name, int type, int clz);

   bool operator<(const DnsQuery& query) const;

   // "Construct" a query at |p|.
   char* Construct(std::map<std::string, uint16_t>* offset_map, char* p,
         char* packet) const;

   void Print() const;
   std::string ToString() const;

   // Getters
   std::string name() const { return name_; }
   uint16_t type() const { return type_; }
   uint16_t clz() const { return clz_; }

  private:
   std::string name_;
   uint16_t type_;
   uint16_t clz_;
};

#endif   // _DNS_QUERY_H_
