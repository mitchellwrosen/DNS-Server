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
   char* Construct(char* p) const;

   void Print() const;
   std::string ToString() const;

   // Host byte-order
   static std::string TypeToString(uint16_t type);
   static std::string ClassToString(uint16_t clz);

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
