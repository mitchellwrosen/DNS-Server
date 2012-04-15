#include <stdint.h>

// A single DNS packet. A DNSPacket consists of a header and one or more
// Records. A Record is either a Query or a ResourceRecord
// Records.
class DNSPacket {
  public:
   DNSPacket(char* data);

   class Query {
     public:
      Query(const DNSPacket& packet);

      // Getters
      char* name() { return name_; }
      uint16_t type() { return type_; }
      uint16_t clz() { return clz_; }

     private:
      const DNSPacket& packet_;

      char* name_;
      uint16_t type_;
      uint16_t clz_;
   };

   class ResourceRecord {
     public:
      ResourceRecord(const DNSPacket& packet);

      // Getters
      char* name() { return name_; }
      uint16_t type() { return type_; }
      uint16_t clz() { return clz_; }
      uint32_t ttl() { return ttl_; }
      uint16_t data_len() { return data_len_; }
      char* data() { return data_; }

     private:
      const DNSPacket& packet_;

      char* name_;
      uint16_t type_;
      uint16_t clz_;
      uint32_t ttl_;
      uint16_t data_len_;
      char* data_;
   };

   friend class Query;
   friend class ResourceRecord;

   // Gets the current query. Returns NULL if the current record is not a query
   // (i.e. is a ResourceRecord) (TODO)
   Query GetQuery();

   // Gets the current resource record. Returns NULL if the current record is
   // not a resource record (i.e. is a Query) (TODO)
   ResourceRecord GetResourceRecord();

   // Prints the entire packet and resets the cur_ pointer.
   Print();
   
   // Flags
   bool qr_flag();   // Query/Response
   uint8_t opcode_flag();    
   bool aa_flag();   // Authoritative Answer
   bool tc_flag();   // Truncation
   bool rd_flag();   // Recursion Desired
   bool ra_flag();   // Recursion Available
   uint8_t rc_flag();   // Response Code


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
