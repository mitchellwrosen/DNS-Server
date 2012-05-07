#ifndef _DNS_PACKET_H_
#define _DNS_PACKET_H_

#include <stdint.h>

#include <map>
#include <list>
#include <string>

#include "smartalloc.h"

typedef std::map<std::string, uint16_t, std::less<std::string>,
      STLsmartalloc<std::pair<std::string, uint16_t> > > OffsetMap;


typedef std::map<std::string, uint16_t, std::less<std::string>,
      STLsmartalloc<std::pair<std::string, uint16_t> > > OffsetMap;

namespace dns_packet_constants {
namespace qr_flag {
extern const int Query;
extern const int Response;
}

namespace opcode {
extern const int Query;
extern const int Query;
extern const int Status;
extern const int Notify;
extern const int Update;
}

namespace response_code {
extern const int NoError;
extern const int FormatError;
extern const int ServerFailure;
extern const int NameError;
extern const int NotImplemented;
extern const int Refused;
extern const int YxDomain;
extern const int YxRrSet;
extern const int NxRrSet;
extern const int NotAuth;
extern const int NotZone;
}

namespace type {
extern const int A;
extern const int NS;
extern const int MD;
extern const int MF;
extern const int CNAME;
extern const int SOA;
extern const int MB;
extern const int MG;
extern const int MR;
extern const int Null;
extern const int WKS;
extern const int PTR;
extern const int HINFO;
extern const int MINFO;
extern const int MX;
extern const int TXT;
extern const int AAAA;
}

namespace clz {
extern const int IN;
extern const int CS;
extern const int CH;
extern const int HS;
}
}

class DnsPacket;

class DnsQuery {
  public:
   DnsQuery(DnsPacket& data);

   // Requires network-order parameters
   DnsQuery(std::string name, int type, int clz);

   bool operator<(const DnsQuery& query) const;

   // "Construct" a query at |p|.
   char* Construct(OffsetMap* offset_map, char* p,
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

class DnsResourceRecord {
  public:
   DnsResourceRecord(DnsPacket& packet);
   DnsResourceRecord(std::string name_, uint16_t type, uint16_t clz,
         uint32_t ttl, uint16_t data_len_, char* data);
   DnsResourceRecord(const DnsResourceRecord& rr);
   virtual ~DnsResourceRecord();

   DnsResourceRecord& operator=(const DnsResourceRecord& record);
   bool operator<(const DnsResourceRecord& record) const;
   bool operator==(const DnsResourceRecord& record) const;

   // "Construct" a resource record onto a buffer, given the beginning of the
   // packet (for name compression) and the current pointer
   char* Construct(OffsetMap* offset_map, char* p,
         char* packet) const;


   // Construct a DnsQuery from the first three fields of this record
   DnsQuery ConstructQuery() const;

   void SubtractFromTtl(uint32_t time);

   std::string ToString() const;

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

typedef std::list<DnsResourceRecord, STLsmartalloc<DnsResourceRecord> > RRList;

// A single DNS packet. A DnsPacket consists of a header and one or more
// Records. A Record is either a Query or a ResourceRecord
// Records.
class DnsPacket {
  public:
   DnsPacket(char* data);

   // Dns name format to string format
   static std::string DnsNameToString(std::string name);

   // Static methods for creating DNS Packets. Each returns a pointer to the
   // next character in the buffer
   // Requires fields to be in network order, except opcode (because it's only
   // 4 bits and gets bit-shifted)
   static int ConstructPacket(char* buf, uint16_t id, bool qr_flag,
      uint16_t opcode, bool aa_flag, bool tc_flag, bool rd_flag, bool ra_flag,
      uint16_t rcode, DnsQuery& query,
      RRList& answer_rrs,
      RRList& authority_rrs,
      RRList& additional_rrs);

   static char* ConstructQuery(char* buf, uint16_t id, uint16_t opcode,
         bool rd_flag, const char* name, uint16_t type, uint16_t clz);

   static char* ConstructQuery(char* buf, uint16_t id, uint16_t opcode,
         bool rd_flag, DnsQuery& query);

   static char* ConstructHeader(char* buf, uint16_t id, bool qr_flag,
         uint16_t opcode, bool aa_flag, bool tc_flag, bool rd_flag,
         bool ra_flag, uint16_t rcode, uint16_t queries, uint16_t answer_rrs,
         uint16_t authority_rrs, uint16_t additional_rrs);

   // "Construct" a <dns name> onto a buffer, possibly compressing the name.
   static char* ConstructDnsName(OffsetMap* offset_map, char* p, char* packet,
         char* name);
   static char* ConstructDnsName(OffsetMap* offset_map, char* p, char* packet,
         std::string name);

   // "Constructs" a query onto a buffer
   char* Construct(char* p);


   friend class DnsQuery;
   friend class DnsResourceRecord;

   // If GetQuery isn't called before GetResourceRecord, bad things will happen
   DnsQuery GetQuery();
   DnsResourceRecord GetResourceRecord();

   // Gets the name pointed to by cur_, advances cur_ to the next field (type)
   std::string GetName();

   // Host byte-order
   static std::string TypeToString(uint16_t type);
   static std::string ClassToString(uint16_t clz);

   void PrintHeader();

   static std::string ShortenName(std::string name);

   // Flags field
   bool qr_flag() { return flags() & 0x8000; }
   uint16_t opcode() { return (flags() & 0x7800) >> 11; }
   bool aa_flag() { return flags() & 0x0400; }
   bool tc_flag() { return flags() & 0x0200; }
   bool rd_flag() { return flags() & 0x0100; }
   bool ra_flag() { return flags() & 0x0080; }
   uint16_t rcode() { return flags() & 0x000F; }

   // Getters
   char* data() { return data_; }
   char* cur() { return cur_; } // necessary?
   uint16_t id() { return id_; }
   uint16_t flags() { return flags_; }
   uint16_t queries() { return queries_; }
   uint16_t answer_rrs() { return answer_rrs_; }
   uint16_t authority_rrs() { return authority_rrs_; }
   uint16_t additional_rrs() { return additional_rrs_; }

  private:
   char* data_;
   char* cur_;
   uint16_t id_;              // network order
   uint16_t flags_;           // host order
   uint16_t queries_;         // host order
   uint16_t answer_rrs_;      // host order
   uint16_t authority_rrs_;   // host order
   uint16_t additional_rrs_;  // host order
};


#endif   // _DNS_PACKET_H_
