#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#include <iostream>

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

using namespace dns_packet_constants;

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

DnsPacket::Query DnsPacket::GetQuery() {
   Query query(*this);
   return query;
}

DnsPacket::ResourceRecord DnsPacket::GetResourceRecord() {
   ResourceRecord rr(*this);
   return rr;
}

void DnsPacket::Print() {
   int i;

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

   std::cout << "Queries: %d" << queries() << std::endl;
   std::cout << "Answer RRs: %d" << answer_rrs() << std::endl;
   std::cout << "Authority RRs: %d" << authority_rrs() << std::endl;
   std::cout << "Additional RRs: %d" << additional_rrs() << std::endl;

   for (i = 0; i < queries_; ++i) {
      Query query = GetQuery();
      std::cout << "Query %d:" << i + 1 << std::endl;
      std::cout << "   Name: %s" << query.name() << std::endl;
      std::cout << "   Type: %d" << query.type() << std::endl;
      std::cout << "   Class: %d" << query.clz() << std::endl;
   }

   for (i = 0; i < answer_rrs_; ++i) {
      ResourceRecord rr = GetResourceRecord();
      std::cout << "Answer RR %d:" << i + 1 << std::endl;
   }
   
   for (i = 0; i < authority_rrs_; ++i) {
      ResourceRecord rr = GetResourceRecord();
      std::cout << "Authority RR %d:" << i + 1 << std::endl;
   }

   for (i = 0; i < additional_rrs_; ++i) {
      ResourceRecord rr = GetResourceRecord();
      std::cout << "Additional RR %d:" << i + 1 << std::endl;
   }
}

uint16_t DnsPacket::id() {
   return htons((uint16_t) data_[kIdOffset]);
}

uint16_t DnsPacket::flags() {
   return (uint16_t) data_[kFlagsOffset];
}

uint16_t DnsPacket::queries() {
   return htons((uint16_t) data_[kQueriesOffset]);
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

// DnsPacket::Query
DnsPacket::Query::Query(DnsPacket& packet)
      : packet_(packet) {
   // The name could be a string, or a two-byte pointer.
   // The first two bits == 11 indicates pointer.
   if ((*packet_.cur_ & 0xc0) == 0xc0) {
      name_ = packet_.data_ + (*packet_.cur_ & 0x3FFF);    
      type_ = ntohs(packet_.cur_[2]);
      clz_ = ntohs(packet_.cur_[4]);
      packet_.cur_ += 6;
   } else {
      name_ = packet_.cur_;
      int name_len_ = strlen(name_);
      type_ = ntohs(packet_.cur_[name_len_ + 1]);
      clz_ = ntohs(packet_.cur_[name_len_ + 3]);
      packet_.cur_ += name_len_ + 5;
   }
}

// DnsPacket::ResourceRecord
// Code duplication, I know. The alternative is to derive ResourceRecord from
// Query to share the common member data, but that is simply an unintuitive
// relationship. A ResourceRecord is-not-a Query.
DnsPacket::ResourceRecord::ResourceRecord(DnsPacket& packet)
      : packet_(packet) {
   // The name could be a string, or a two-byte pointer.
   // The first two bits == 11 indicates pointer.
   if ((*packet_.cur_ & 0xc0) == 0xc0) {
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
      packet_.cur_ += name_len_ + 11 + data_len_;
   }
}
