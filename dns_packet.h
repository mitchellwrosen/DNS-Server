#ifndef _DNS_PACKET_H_
#define _DNS_PACKET_H_

#include <stdint.h>

#include <vector>

#include "dns_query.h"
#include "dns_resource_record.h"

namespace dns_packet_constants {
extern const int kQrFlagQuery;
extern const int kQrFlagResponse;

extern const int kOpcodeQuery;
extern const int kOpcodeInverseQuery;
extern const int kOpcodeStatus;
extern const int kOpcodeNotify;
extern const int kOpcodeUpdate;

extern const int kResponseCodeNoError;
extern const int kResponseCodeFormatError;
extern const int kResponseCodeServerFailure;
extern const int kResponseCodeNameError;
extern const int kResponseCodeNotImplemented;
extern const int kResponseCodeRefused;
extern const int kResponseCodeYxDomain;
extern const int kResponseCodeYxRrSet;
extern const int kResponseCodeNxRrSet;
extern const int kResponseCodeNotAuth;
extern const int kResponseCodeNotZone;
}

// A single DNS packet. A DnsPacket consists of a header and one or more
// Records. A Record is either a Query or a ResourceRecord
// Records.
class DnsPacket {
  public:
   DnsPacket(char* data);


   struct Flags {
      uint16_t qr:1;
      uint16_t opcode:4;
      uint16_t aa:1;
      uint16_t tc:1;
      uint16_t rd:1;
      uint16_t ra:1;
      uint16_t zeros:3;
      uint16_t rcode:4;
   } __attribute__((packed));

   // Static methods for creating DNS Packets. Each returns a pointer to the
   // next character in the buffer
   // Requires fields to be in network order
   static char* ConstructHeader(char* buf, uint16_t id, bool qr_flag,
         uint8_t opcode, bool aa_flag, bool tc_flag, bool rd_flag,
         bool ra_flag, uint8_t rcode, uint16_t queries, uint16_t answer_rrs,
         uint16_t authority_rrs, uint16_t additional_rrs);

   static uint16_t ConstructFlags(bool qr_flag, uint8_t opcode, bool aa_flag,
         bool tc_flag, bool rd_flag, bool ra_flag, uint8_t rcode);

   // Gets the name pointed to by *p, advances *p to the next field (type)
   static std::string GetName(char* packet, char** strpp);

   // Advances *p to the next field (type)
   void AdvancePastName(char** strpp);

   // Advances *p to the next ResourceRecord
   void AdvanceToNextResourceRecord(char** rrpp);

   void Print();
   void PrintHeader();

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
   uint16_t id() { return id_; }
   uint16_t flags() { return flags_; }
   uint16_t queries() { return queries_; }
   uint16_t answer_rrs() { return answer_rrs_; }
   uint16_t authority_rrs() { return authority_rrs_; }
   uint16_t additional_rrs() { return additional_rrs_; }
   DnsQuery GetQuery() { return query_; }
   DnsResourceRecord GetAnswerResourceRecord(int index);
   DnsResourceRecord GetAuthorityResourceRecord(int index);
   DnsResourceRecord GetAdditionalResourceRecord(int index);

  private:
   char* data_;
   uint16_t id_;
   uint16_t flags_;
   uint16_t queries_;
   uint16_t answer_rrs_;
   uint16_t authority_rrs_;
   uint16_t additional_rrs_;

   DnsQuery query_; // only 1
   std::vector<char*> answer_rrs_vec_;
   std::vector<char*> authority_rrs_vec_;
   std::vector<char*> additional_rrs_vec_;
};

#endif   // _DNS_PACKET_H_
