#ifndef _DNS_PACKET_H_
#define _DNS_PACKET_H_

#include <stdint.h>

#include <vector>

#include "dns_query.h"

class DnsResourceRecord;

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
}

namespace clz {
extern const int IN;
extern const int CS;
extern const int CH;
extern const int HS;
}
}

// A single DNS packet. A DnsPacket consists of a header and one or more
// Records. A Record is either a Query or a ResourceRecord
// Records.
class DnsPacket {
  public:
   DnsPacket(char* data);

   // Construct a DnsQuery at buf, return the number of bytes written
   static int ConstructQuery(char* buf, uint16_t id, uint16_t opcode, 
         bool rd_flag, const char* name, uint16_t type, uint16_t clz);
   
   // Static methods for creating DNS Packets. Each returns a pointer to the
   // next character in the buffer
   // Requires fields to be in network order
   static char* ConstructHeader(char* buf, uint16_t id, bool qr_flag,
         uint16_t opcode, bool aa_flag, bool tc_flag, bool rd_flag,
         bool ra_flag, uint16_t rcode, uint16_t queries, uint16_t answer_rrs,
         uint16_t authority_rrs, uint16_t additional_rrs);

   friend class DnsQuery;
   friend class DnsResourceRecord;

   // If GetQuery isn't called before GetResourceRecord, bad things will happen
   DnsQuery GetQuery();
   DnsResourceRecord GetResourceRecord();

   // Gets the name pointed to by cur_, advances cur_ to the next field (type)
   std::string GetName();

   void PrintHeader();

   static std::string ShortenName(std::string name);

   // Flags field
   bool qr_flag() { return flags() & 0x8000; }
   uint8_t opcode() { return (flags() & 0x7800) >> 11; }
   bool aa_flag() { return flags() & 0x0400; }
   bool tc_flag() { return flags() & 0x0200; }
   bool rd_flag() { return flags() & 0x0100; }
   bool ra_flag() { return flags() & 0x0080; }
   uint8_t rcode() { return flags() & 0x000F; }

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
