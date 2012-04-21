#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#include <iostream>

#include "dns_packet.h"
#include "dns_query.h"
#include "dns_resource_record.h"

namespace dns_packet_constants {
namespace qr_flag {
const int Query = 0;
const int Response = 1;
}

namespace opcode {
const int Query = 0;
const int InverseQuery = 1;
const int Status = 2;
const int Notify = 3;
const int Update = 4;
}

namespace response_code {
const int NoError = 0;
const int FormatError = 1;
const int ServerFailure = 2;
const int NameError = 3;
const int NotImplemented = 4;
const int Refused = 5;
const int YxDomain = 6;
const int YxRrSet = 7;
const int NxRrSet = 8;
const int NotAuth = 9;
const int NotZone = 10;
}

namespace type {
const int A = 1;
const int NS = 2;
const int MD = 3;
const int MF = 4;
const int CNAME = 5;
const int SOA = 6;
const int MB = 7;
const int MG = 8;
const int MR = 9;
const int Null = 10;
const int WKS = 11;
const int PTR = 12;
const int HINFO = 13;
const int MINFO = 14;
const int MX = 15;
const int TXT = 16;
}

namespace clz {
const int IN = 1;
const int CS = 2;
const int CH = 3;
const int HS = 4;
}
}

namespace {
const int kIdOffset = 0;
const int kFlagsOffset = 2;
const int kQueriesOffset = 4;
const int kAnswerRrsOffset = 6;
const int kAuthorityRrsOffset = 8;
const int kAdditionalRrsOffset = 10;
const int kFirstQueryOffset = 12;
}

using namespace dns_packet_constants;

DnsPacket::DnsPacket(char* data)
      : data_(data),
        cur_(data + kFirstQueryOffset);
        id_(ntohs(data[kIdOffset])),
        flags_(data[kFlagsOffset]),
        queries_(ntohs(data[kQueriesOffset])),
        answer_rrs_(ntohs(data[kAnswerRrsOffset])),
        authority_rrs_(ntohs(data[kAuthorityRrsOffset])),
        additional_rrs_(ntohs(data[kAdditionalRrsOffset])) {
   query_(*this);
}

std::string DnsPacket::GetName() {
   bool ptr_found = false;
   char* p = cur_;
   std::string name;

   while (*p) {
      if ((*p & 0xc0) == 0xc0) {
         if (!ptr_found) {
            ptr_found = true;
            cur_ = p + 2;
         }
         p = packet + ntohs(*((uint16_t*) p) & 0x3FFF);
      }

      // p is now pointing at a number. append that many chars to name, plus
      // one for the number itself
      name.append(p, *p + 1);
      p += *p + 1;
   }

   // If a pointer was used to resolve the name, cur_ was already set.
   // Otherwise, p is pointing at the null byte after the name. Set cur_
   // accordingly.
   if (!ptr_found)
      cur_ = p + 1;

   return name;
}

// static
char* DnsPacket::ConstructHeader(char* buf, uint16_t id, bool qr_flag,
      uint8_t opcode, bool aa_flag, bool tc_flag, bool rd_flag, bool ra_flag,
      uint8_t rcode, uint16_t queries, uint16_t answer_rrs,
      uint16_t authority_rrs, uint16_t additional_rrs) {
   memcpy(buf, &id, sizeof(uint16_t));

   uint16_t flags = ConstructFlags(qr_flag, opcode, aa_flag, tc_flag,
      rd_flag, ra_flag, rcode);
   memcpy(buf + 2, &flags, sizeof(uint16_t));

   memcpy(buf + 4, &queries, sizeof(uint16_t));
   memcpy(buf + 6, &answer_rrs, sizeof(uint16_t));
   memcpy(buf + 8, &authority_rrs, sizeof(uint16_t));
   memcpy(buf + 10, &additional_rrs, sizeof(uint16_t));

   return buf + 12;
}

// static
uint16_t DnsPacket::ConstructFlags(bool qr_flag, uint8_t opcode,
      bool aa_flag, bool tc_flag, bool rd_flag, bool ra_flag, uint8_t rcode) {
   Flags flags;
   memset(&flags, 0, sizeof(Flags));

   flags.qr = qr_flag;
   flags.opcode = opcode;
   flags.aa = aa_flag;
   flags.tc = tc_flag;
   flags.rd = rd_flag;
   flags.ra = ra_flag;
   flags.rcode = rcode;

   // Holy shit O.O
   return htons(*reinterpret_cast<uint16_t*>(&flags));
}

DnsResourceRecord DnsPacket::GetResourceRecord() {
   DnsResourceRecord rr(*this);
   return rr;
}

void DnsPacket::Print() {
   if (queries_ != 1) {
      std::cout << "Error in DnsPacket::Print(): Packet has %d queries."
            << queries_ << std::endl;
      return;
   }

   int i;

   PrintHeader();
   query_.Print();

   for (i = 0; i < answer_rrs_; ++i)
      GetAnswerResourceRecord(i).Print();

   for (i = 0; i < authority_rrs_; ++i)
      GetAuthorityResourceRecord(i).Print();

   for (i = 0; i < additional_rrs_; ++i)
      GetAdditionalResourceRecord(i).Print();
}

void DnsPacket::PrintHeader() {
   std::cout << "DNS Packet" << std::endl;
   std::cout << "==========" << std::endl;
   std::cout << "Id: %d" << id() << std::endl;

   if (qr_flag() == kQrFlagQuery)
      std::cout << "Query/Response: 1 (Response)" << std::endl;
   else
      std::cout << "Query/Response: 0 (Query)" << std::endl;

   std::string opcode_str;
   switch (opcode()) {
      case kOpcodeQuery:
         opcode_str = "Query";
         break;
      case kOpcodeInverseQuery:
         opcode_str = "Inverse Query";
         break;
      case kOpcodeStatus:
         opcode_str = "Status";
         break;
      case kOpcodeNotify:
         opcode_str = "Notify";
         break;
      case kOpcodeUpdate:
         opcode_str = "Update";
         break;
      default:
         opcode_str = "UNRECOGNIZED";
         break;
   }
   std::cout << "Opcode: %d (%s)" << opcode() << opcode_str << std::endl;

   std::cout << "Authoritative Answer: %d" << aa_flag() << std::endl;
   std::cout << "Truncation: %d" << tc_flag() << std::endl;
   std::cout << "Recursion Desired: %d" << rd_flag() << std::endl;
   std::cout << "Recursion Available: %d" << ra_flag() << std::endl;

   std::string rcode_str;
   switch(rcode()) {
      case kResponseCodeNoError:
         rcode_str = "No Error";
         break;
      case kResponseCodeFormatError:
         rcode_str = "Format Error";
         break;
      case kResponseCodeServerFailure:
         rcode_str = "Server Failure";
         break;
      case kResponseCodeNameError:
         rcode_str = "Name Error";
         break;
      case kResponseCodeRefused:
         rcode_str = "Refused";
         break;
      case kResponseCodeYxDomain:
         rcode_str = "YX Domain";
         break;
      case kResponseCodeYxRrSet:
         rcode_str = "YX RR Set";
         break;
      case kResponseCodeNxRrSet:
         rcode_str = "NX RR Set";
         break;
      case kResponseCodeNotAuth:
         rcode_str = "Not Auth";
         break;
      case kResponseCodeNotZone:
         rcode_str = "Not Zone";
         break;
   }
   std::cout << "Response Code: %d (%s)" << rcode() << rcode_str << std::endl;

   std::cout << "Queries: %d" << queries_ << std::endl;
   std::cout << "Answer RRs: %d" << answer_rrs_ << std::endl;
   std::cout << "Authority RRs: %d" << authority_rrs_ << std::endl;
   std::cout << "Additional RRs: %d" << additional_rrs_ << std::endl;
}
