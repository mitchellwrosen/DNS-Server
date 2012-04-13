#include <stdint.h>

// A single DNS packet. A DNSPacket consists of a header and one or more
// Records. A Record is either a Query or a ResourceRecord
// Records.
class DNSPacket {
  public:
   DNSPacket(char* data);

   extern const int kIdOffset;
   extern const int kFlagsOffset;
   extern const int kQueriesOffset;
   extern const int kAnswerRrsOffset;
   extern const int kAuthorityRrsOffset;
   extern const int kAdditionalRrsOffset;

   class Record {
     public:
      Record(const DNSPacket& packet);

      Record* operator++();

     protected:
      const DNSPacket& packet_;
      uint16_t type_;
      uint16_t clz_;
   }

   class Query : public Record {
     public:
      Query(const DNSPacket& packet);

     private:
      const DNSPacket& packet_;

      char* name_;
   }

   class ResourceRecord : public Record {
     public:
      ResourceRecord(const DNSPacket& packet);

     private:
      const DNSPacket& packet;

      uint16_t name_;
      uint32_t ttl_;
      uint16_t len_;
      char* data_;
   };

   friend class Header;
   friend class Record;

   // Getters
   char* data() { return data_; }
   struct Header* header() { return (struct Header*) data_; }
   char* cur() { return cur_; }

   Record* cur_record();
   uint16_t id();
   uint16_t flags();
   uint16_t answer_rrs();
   uint16_t authority_rrs();
   uint16_t additional_rrs();

  private:
   char* data_;
   char* cur_; // Points to current ResourceRecord

   uint16_t id_;
   uint16_t flags_;
   uint16_t answer_rrs_;
   uint16_t authority_rrs_;
   uint16_t additional_rrs_;
};
