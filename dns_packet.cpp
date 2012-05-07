#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#include <iostream>
#include <map>
#include <list>
#include <utility>

#include "debug.h"

#include "checksum.h"
#include "smartalloc.h"

#include "dns_packet.h"

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
const int AAAA = 28;
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

namespace constants = dns_packet_constants;

DnsPacket::DnsPacket(char* data)
      : data_(data),
        cur_(data + kFirstQueryOffset),
        id_(*((uint16_t*) (data + kIdOffset))),
        flags_(ntohs(*((uint16_t*) (data + kFlagsOffset)))),
        queries_(ntohs(*((uint16_t*) (data + kQueriesOffset)))),
        answer_rrs_(ntohs(*((uint16_t*) (data + kAnswerRrsOffset)))),
        authority_rrs_(ntohs(*((uint16_t*) (data + kAuthorityRrsOffset)))),
        additional_rrs_(ntohs(*((uint16_t*) (data + kAdditionalRrsOffset)))) { }

std::string DnsPacket::DnsNameToString(std::string name) {
   std::string ret;
   const char* c_name = name.c_str();
   const char* p = c_name;

   while (*p) {
      ret.push_back('[');
      ret.push_back(*p + '0');
      ret.push_back(']');
      ret.append(p+1, *p);
      p += *p+1;
   }

   return ret;
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
         p = data_ + (ntohs(*((uint16_t*) p)) & 0x3FFF);
      }

      // p is now pointing at a number. append that many chars to name, plus
      // one for the number itself
      int num_chars = *p+1;
      for (int i = 0; i < num_chars; ++i) {
         if (isalpha(*p))
            name.push_back(tolower(*p));
         else
            name.push_back(*p);

         p++;
      }

      //name.append(p, *p + 1);
      //p += *p + 1;
   }

   // If a pointer was used to resolve the name, cur_ was already set.
   // Otherwise, p is pointing at the null byte after the name. Set cur_
   // accordingly.
   if (!ptr_found)
      cur_ = p + 1;

   return name;
}

// static
char* DnsPacket::ConstructQuery(char* buf, uint16_t id, uint16_t opcode,
      bool rd_flag, const char* name, uint16_t type, uint16_t clz) {
   char *p = ConstructHeader(buf, id, constants::qr_flag::Query, opcode,
         false, false, rd_flag, false, 0);
   int name_len = strlen(name);
   memcpy(p, name, name_len + 1);
   memcpy(p + name_len + 1, &type, sizeof(uint16_t));
   memcpy(p + name_len + 3, &clz, sizeof(uint16_t));
   return p + name_len + 5;
}

// static
int DnsPacket::ConstructPacket(char* buf, uint16_t id, bool qr_flag,
      uint16_t opcode, bool aa_flag, bool tc_flag, bool rd_flag, bool ra_flag,
      uint16_t rcode, DnsQuery& query,
      RRList& answer_rrs,
      RRList& authority_rrs,
      RRList& additional_rrs) {
   Header* header = (struct Header*) buf;
   char* p = ConstructHeader(buf, id, qr_flag, opcode, aa_flag, tc_flag,
         rd_flag, ra_flag, rcode);
   char* old_p = p;
   bool stop_writing = false;

   // Create offset map
   OffsetMap offset_map;

   // Write the query
   p = query.Construct(&offset_map, p, buf);

   uint16_t answers_written = 0;
   uint16_t authorities_written = 0;
   uint16_t additionals_written = 0;

   // Write as many answers as we can
   RRList::iterator it;
   for (it = answer_rrs.begin(); it != answer_rrs.end(); ++it) {
      old_p = p;
      p = it->Construct(&offset_map, p, buf);
      if (p - buf >= 512) {
         stop_writing = true;
         break;
      }

      answers_written++;
   }

   // Check to see if we went over 512
   if (stop_writing)
      return old_p - buf;

   // Write as many authorities as we can
   for (it = authority_rrs.begin(); it != authority_rrs.end(); ++it) {
      old_p = p;
      p = it->Construct(&offset_map, p, buf);
      if (p - buf >= 512) {
         stop_writing = true;
         break;
      }

      authorities_written++;
   }

   // Check to see if we went over 512
   if (stop_writing)
      return old_p - buf;

   // Write as many additionals as we can
   for (it = additional_rrs.begin(); it != additional_rrs.end(); ++it) {
      old_p = p;
      p = it->Construct(&offset_map, p, buf);
      if (p - buf >= 512) {
         stop_writing = true;
         break;
      }

      additionals_written++;
   }

   // Check to see if we went over 512
   if (stop_writing)
      return old_p - buf;

   // Set the count header fields
   header->answer_rrs = htons(answers_written);
   header->authority_rrs = htons(authorities_written);
   header->additional_rrs = htons(additionals_written);

   return p - buf;
}

char* DnsPacket::ConstructQuery(char* buf, uint16_t id, uint16_t opcode,
      bool rd_flag, DnsQuery& query) {
   return ConstructQuery(buf, id, opcode, rd_flag, query.name().c_str(),
         query.type(), query.clz());
}

char* DnsPacket::ConstructHeader(char* buf, uint16_t id, bool qr_flag,
      uint16_t opcode, bool aa_flag, bool tc_flag, bool rd_flag, bool ra_flag,
      uint16_t rcode) {
   Header* header = (struct Header*) buf;

   header->id = id;

   uint16_t flags = rcode; // last bits match up
   if (qr_flag) flags |= 0x8000;
   flags |= (opcode << 11);
   if (aa_flag) flags |= 0x0400;
   if (tc_flag) flags |= 0x0200;
   if (rd_flag) flags |= 0x0100;
   if (ra_flag) flags |= 0x0080;
   flags = htons(flags);

   header->flags = flags;
   header->queries = ntohs(1);
   header->answer_rrs = 0;
   header->authority_rrs = 0;
   header->additional_rrs = 0;

   return buf + sizeof(Header);
}

// static
char* DnsPacket::ConstructDnsName(OffsetMap* offset_map, char* p, char* packet,
      char* name) {
   return ConstructDnsName(offset_map, p, packet, std::string(name));
}

// static
char* DnsPacket::ConstructDnsName(OffsetMap* offset_map, char* p, char* packet,
      std::string name) {
   OffsetMap::iterator it;
   bool ptr_used = false;

   while (name.length()) {
      it = offset_map->find(name);
      if (it != offset_map->end()) {
         ptr_used = true;

         // write the pointer
         uint16_t offset = htons(it->second | 0xc000);
         memcpy(p, &offset, 2);
         p += 2;
         break;
      }

      // no match found --
      // 1. write the first octet of the current name to the packet
      const char* c_name = name.c_str();
      memcpy(p, c_name, *c_name+1);

      // 2. add the current name to the offset map, then advance p
      offset_map->insert(std::pair<std::string, uint16_t>(name, p - packet));
      p += *c_name+1;

      // 3. shorten the current name
      name = DnsPacket::ShortenName(name);
   }

   // Write null terminating byte of string
   if (!ptr_used)
      *p++ = 0;

   return p;
}

DnsQuery DnsPacket::GetQuery() {
   DnsQuery query(*this);
   return query;
}

DnsResourceRecord DnsPacket::GetResourceRecord() {
   DnsResourceRecord rr(*this);
   return rr;
}

// static
std::string DnsPacket::ShortenName(std::string name) {
   return name.substr(name.at(0)+1);
}

// static
std::string DnsPacket::TypeToString(uint16_t type) {
   if (type == constants::type::A)
      return "A";
   else if (type == constants::type::AAAA)
      return "AAAA";
   else if (type == constants::type::NS)
      return "NS";
   else if (type == constants::type::CNAME)
      return "CNAME";
   else if (type == constants::type::SOA)
      return "SOA";
   else if (type == constants::type::PTR)
      return "PTR";
   else if (type == constants::type::MX)
      return "MX";
   else
      return "UNKNOWN"; //TODO finish else-if chain
}

// static
std::string DnsPacket::ClassToString(uint16_t clz) {
   if (clz == constants::clz::IN)
      return "IN";
   else if (clz == constants::clz::CS)
      return "CS";
   else if (clz == constants::clz::CH)
      return "CH";
   else if (clz == constants::clz::HS)
      return "HS";
   else
      return "UNKNOWN";
}

void DnsPacket::PrintHeader() {
   std::cout << "DNS Packet" << std::endl;
   std::cout << "==========" << std::endl;
   std::cout << "Id: " << id() << std::endl;

   if (qr_flag() == constants::qr_flag::Response)
      std::cout << "Query/Response: 1 (Response)" << std::endl;
   else
      std::cout << "Query/Response: 0 (Query)" << std::endl;

   std::string opcode_str;
   switch (opcode()) {
      case constants::opcode::Query:
         opcode_str = "Query";
         break;
      case constants::opcode::InverseQuery:
         opcode_str = "Inverse Query";
         break;
      case constants::opcode::Status:
         opcode_str = "Status";
         break;
      case constants::opcode::Notify:
         opcode_str = "Notify";
         break;
      case constants::opcode::Update:
         opcode_str = "Update";
         break;
      default:
         opcode_str = "UNRECOGNIZED";
         break;
   }
   std::cout << "Opcode: " << (int) opcode() << " (" << opcode_str << ")" <<
         std::endl;

   std::cout << "Authoritative Answer: " << aa_flag() << std::endl;
   std::cout << "Truncation: " << tc_flag() << std::endl;
   std::cout << "Recursion Desired: " << rd_flag() << std::endl;
   std::cout << "Recursion Available: " << ra_flag() << std::endl;

   std::string rcode_str;
   switch(rcode()) {
      case constants::response_code::NoError:
         rcode_str = "No Error";
         break;
      case constants::response_code::FormatError:
         rcode_str = "Format Error";
         break;
      case constants::response_code::ServerFailure:
         rcode_str = "Server Failure";
         break;
      case constants::response_code::NameError:
         rcode_str = "Name Error";
         break;
      case constants::response_code::Refused:
         rcode_str = "Refused";
         break;
      case constants::response_code::YxDomain:
         rcode_str = "YX Domain";
         break;
      case constants::response_code::YxRrSet:
         rcode_str = "YX RR Set";
         break;
      case constants::response_code::NxRrSet:
         rcode_str = "NX RR Set";
         break;
      case constants::response_code::NotAuth:
         rcode_str = "Not Auth";
         break;
      case constants::response_code::NotZone:
         rcode_str = "Not Zone";
         break;
   }
   std::cout << "Response Code: " << (int) rcode() << " (" << rcode_str << ")"
         << std::endl;

   std::cout << "Queries: " << (int) queries_ << std::endl;
   std::cout << "Answer RRs: " << (int) answer_rrs_ << std::endl;
   std::cout << "Authority RRs: " << (int) authority_rrs_ << std::endl;
   std::cout << "Additional RRs: " << (int) additional_rrs_ << std::endl;
}
