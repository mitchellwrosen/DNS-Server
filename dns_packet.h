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
      Query(const DnsPacket& packet);

      // Getters
      char* name() { return name_; }
      uint16_t type() { return type_; }
      uint16_t clz() { return clz_; }

     private:
      const DnsPacket& packet_;

      char* name_;
      uint16_t type_;
      uint16_t clz_;
   };

   class ResourceRecord {
     public:
      ResourceRecord(const DnsPacket& packet);

      // Getters
      char* name() { return name_; }
      uint16_t type() { return type_; }
      uint16_t clz() { return clz_; }
      uint32_t ttl() { return ttl_; }
      uint16_t data_len() { return data_len_; }
      char* data() { return data_; }

     private:
      const DnsPacket& packet_;

      char* name_;
      uint16_t type_;
      uint16_t clz_;
      uint32_t ttl_;
      uint16_t data_len_;
      char* data_;
   };

   friend class Query;
   friend class ResourceRecord;

   // Static methods for creating DNS Packets
   static void Construct





   // Gets the current query. Returns NULL if the current record is not a query
   // (i.e. is a ResourceRecord) (TODO)
   Query GetQuery();

   // Gets the current resource record. Returns NULL if the current record is
   // not a resource record (i.e. is a Query) (TODO)
   ResourceRecord GetResourceRecord();

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
   struct Header* header() { return (struct Header*) data_; }
   char* cur() { return cur_; }

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
