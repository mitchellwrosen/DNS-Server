#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#include "dns_packet.h"

namespace dns_packet_constants {
const int kQrFlagQuery = 0;
const int kQrFlagResponse = 1;

const int kOpcodeQuery = 0;
const int kOpcodeInverseQuery = 1;
const int kOpcodeStatus = 2;
const int kOpcodeNotify = 3;
const int kOpcodeUpdate = 4;

const int kResponseCodeNoError = 0;
const int kResponseCodeFormatError = 1;
const int kResponseCodeServerFailure = 2;
const int kResponseCodeNameError = 3;
const int kResponseCodeNotImplemented = 4;
const int kResponseCodeRefused = 5;
const int kResponseCodeYxDomain = 6;
const int kResponseCodeYxRrSet = 7;
const int kResponseCodeNxRrSet = 8;
const int kResponseCodeNotAuth = 9;
const int kResponseCodeNotZone = 10;
} 

namespace {
const int kIdOffset = 0;
const int kFlagsOffset = 2;
const int kQueriesOffset = 4;
const int kAnswerRrsOffset = 6;
const int kAuthorityRrsOffset = 8;
const int kAdditionalRrsOffset = 10;
const int kFirstRecordOffset = 12;
}

// DnsPacket
DnsPacket::DnsPacket(char* data)
      : data_(data),
        cur_(data + kFirstRecordOffset),
        id_(ntohs(data[kIdOffset])),
        flags_(data[kFlagsOffset]),
        queries_(ntohs(data[kQueriesOffset])),
        answer_rrs_(ntohs(data[kAnswerRrsOffset])),
        authority_rrs_(ntohs(data[kAuthorityRrsOffset])),
        additional_rrs_(ntohs(data[kAdditionalRrsOffset])) {
}

uint16_t DnsPacket::id() {
   return htons((uint16_t) data_[kIdOffset]);
}

uint16_t DnsPacket::flags() {
   return (uint16_t) data_[kFlagsOffset];
}

uint16_t DnsPacket::queries() {
   return htons((uint16_t) data_[kQueriesOffset])
}

uint16_t DnsPacket::answer_rrs() {
   return htons((uint16_t) data_[kAnswerRrsOffset]);
}

uint16_t DnsPacket::authority_rrs() {
   return htons((uint16_t) data_[kAuthorityRrsOffset]);
}

uint16_t DnsPacket::additional_rrs() {
   return htons((uint16_t) data_[kAdditionalRrsOffset]);
}

DnsPacket::Query DnsPacket::GetQuery() {
   return Query query(*this);
}

DnsPacket::ResourceRecord DnsPacket::GetResourceRecord() {
   return ResourceRecord rr(*this);
}

DnsPacket::Print() {
   int i;

   fprintf(stdout, "DNS Packet\n");
   fprintf(stdout, "==========\n");
   fprintf(stdout, "Id: %d\n", id());
   
   if (qr_flag() == kQRFlagQuery)
      fprintf(stdout, "Query/Response: 1 (Response)\n");
   else
      fprintf(stdout, "Query/Response: 0 (Query)\n");
   
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
   fprintf(stdout, "Opcode: %d (%s)\n", opcode(), opcode_str);

   fprintf(stdout, "Authoritative Answer: %d\n", aa_flag());
   fprintf(stdout, "Truncation: %d\n", tc_flag());
   fprintf(stdout, "Recursion Desired: %d\n", rd_flag());
   fprintf(stdout, "Recursion Available: %d\n", ra_flag());
   
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
   fprintf(stdout, "Response Code: %d (%s)\n", rcode(), rcode_str);

   fprintf(stdout, "Queries: %d\n", queries());
   fprintf(stdout, "Answer RRs: %d\n", answer_rrs());
   fprintf(stdout, "Authority RRs: %d\n", authority_rrs());
   fprintf(stdout, "Additional RRs: %d\n", additional_rrs());

   for (i = 0; i < queries_; ++i) {
      Query query = GetQuery();
      fprintf(stdout, "Query %d:\n", i + 1);
      fprintf(stdout, "   Name: %s\n", query.name());
      fprintf(stdout, "   Type: %d\n", query.type());
      fprintf(stdout, "   Class: %d\n", query.clz());
   }

   for (i = 0; i < answer_rrs_; ++i) {
      ResourceRequest rr = GetResourceRequest();
      fprintf(stdout, "Answer RR %d:\n", i + i);
   }
   
   for (i = 0; i < authority_rrs_; ++i) {
      ResourceRequest rr = GetResourceRequest();
      fprintf(stdout, "Authority RR %d:\n", i + i);
   }

   for (i = 0; i < additional_rrs_; ++i) {
      ResourceRequest rr = GetResourceRequest();
      fprintf(stdout, "Additional RR %d:\n", i + i);
   }
}

// DnsPacket::Query
DnsPacket::Query::Query(const DnsPacket& packet)
      : packet_(packet) {
   // The name could be a string, or a two-byte pointer.
   // The first two bits == 11 indicates pointer.
   if (*packet_.cur_ & 0xc0 == 0xc0) {
      name_ = packet_.data_ + (*packet_.cur_ & 0x3FFF);    
      type_ = ntohs(packet_.cur_[2]);
      clz_ = ntohs(packet_.cur_[4]);
      packet_.cur_ += 6;
   } else {
      name_ = packet_.cur_;
      int name_len_ = strlen(name_);
      type_ = ntohs(packet_.cur_[name_len_ + 1]);
      clz_ = ntohs(packet_.cur_[name_len_ + 3]);
      packet_.cur += name_len_ + 5;
   }
}

// DnsPacket::ResourceRecord
// Code duplication, I know. The alternative is to derive ResourceRecord from
// Query to share the common member data, but that is simply an unintuitive
// relationship. A ResourceRecord is-not-a Query.
DnsPacket::ResourceRecord::ResourceRecord(const DnsPacket& packet)
      : packet_(packet) {
   // The name could be a string, or a two-byte pointer.
   // The first two bits == 11 indicates pointer.
   if (*packet_.cur_ & 0xc0 == 0xc0) {
      name_ = packet_.data_ + (*packet_.cur_ & 0x3FFF);    
      type_ = ntohs(packet_.cur_[2]);
      clz_ = ntohs(packet_.cur_[4]);
      ttl_ = ntohl(packet_.cur_[6]);
      data_len_ = ntohs(packet_.cur_[10]);
      data_ = packet_.cur_ + 12;
      packet_.cur_ += 12 + data_len_;
   } else {
      name_ = packet_.cur_;
      int name_len_ = strlen(name_);
      type_ = ntohs(packet_.cur_[name_len_ + 1]);
      clz_ = ntohs(packet_.cur_[name_len_ + 3]);
      ttl_ = ntohl(packet_.cur_[name_len_ + 5]);
      data_len_ = ntohs(packet_.cur_[name_len_ + 9]);
      data_ = packet_.cur_ + name_len_ + 11;
      packet_.cur += name_len_ + 11 + data_len_;
   }
}
