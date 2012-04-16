#include <stdint.h>

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

   class Query {
     public:
      Query(DnsPacket& packet);

      // Getters
      std::string name() { return name_; }
      uint16_t type() { return type_; }
      uint16_t clz() { return clz_; }

     private:
      DnsPacket& packet_;

      std::string name_;
      uint16_t type_;
      uint16_t clz_;
   };

   class ResourceRecord {
     public:
      ResourceRecord(DnsPacket& packet);

      // Getters
      std::string name() { return name_; }
      uint16_t type() { return type_; }
      uint16_t clz() { return clz_; }
      uint32_t ttl() { return ttl_; }
      uint16_t data_len() { return data_len_; }
      char* data() { return data_; }

     private:
      DnsPacket& packet_;

      std::string name_;
      uint16_t type_;
      uint16_t clz_;
      uint32_t ttl_;
      uint16_t data_len_;
      char* data_;
   };

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

   friend class Query;
   friend class ResourceRecord;

   // Static methods for creating DNS Packets. Each returns a pointer to the
   // next character in the buffer
   // Requires fields to be in network order
   static char* ConstructHeader(char* buf, uint16_t id, bool qr_flag,
         uint8_t opcode, bool aa_flag, bool tc_flag, bool rd_flag,
         bool ra_flag, uint8_t rcode, uint16_t queries, uint16_t answer_rrs,
         uint16_t authority_rrs, uint16_t additional_rrs);
   
   static uint16_t ConstructFlags(bool qr_flag, uint8_t opcode, bool aa_flag,
         bool tc_flag, bool rd_flag, bool ra_flag, uint8_t rcode);

   // Gets the current query. Returns NULL if the current record is not a query
   // (i.e. is a ResourceRecord) (TODO)
   Query GetQuery();

   // Gets the current resource record. Returns NULL if the current record is
   // not a resource record (i.e. is a Query) (TODO)
   ResourceRecord GetResourceRecord();

   // Gets the name pointed to by cur_, advances cur_ accordingly.
   std::string GetName();

   // Prints the entire packet and resets the cur_ pointer.
   void Print();
   
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

   uint16_t id();
   uint16_t flags();
   uint16_t queries();
   uint16_t answer_rrs();
   uint16_t authority_rrs();
   uint16_t additional_rrs();

  private:
   char* data_;
   char* cur_; // Points to the next record to be fetched
   int cur_record_num_;

   uint16_t id_;
   uint16_t flags_;
   uint16_t queries_;
   uint16_t answer_rrs_;
   uint16_t authority_rrs_;
   uint16_t additional_rrs_;
};
