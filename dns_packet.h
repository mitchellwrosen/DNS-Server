#include <stdint.h>

// A single DNS packet. A DNSPacket consists of a header and one or more
// Records. A Record is either a Query or a ResourceRecord
// Records.
class DNSPacket {
  public:
   DNSPacket(char* data);

   // A Record is either a Query or a ResourceRecord. A Record gets is data by
   // accessing packet_.cur_, which always points to the first byte of the
   // current record.
   class Record {
     public:
      Record(const DNSPacket& packet);

      virtual const Record& operator++();

     protected:
      const DNSPacket& packet_;
      uint16_t type_;
      uint16_t clz_;
   }

   class Query : public Record {
     public:
      Query(const DNSPacket& packet);

      const Record& operator++();

     private:
      const DNSPacket& packet_;

      char* name_;
      int name_len_;
   }

   class ResourceRecord : public Record {
     public:
      ResourceRecord(const DNSPacket& packet);

      const Record& operator++();

     private:
      const DNSPacket& packet_;

      uint16_t name_;
      uint32_t ttl_;
      uint16_t len_;
      char* data_;
   };

   friend class Record;

   const Record& FirstRecord();

   // Getters
   char* data() { return data_; }
   struct Header* header() { return (struct Header*) data_; }
   char* cur() { return cur_; }
   const Record& cur_record() { return cur_record_; }

   uint16_t id();
   uint16_t flags();
   uint16_t answer_rrs();
   uint16_t authority_rrs();
   uint16_t additional_rrs();

  private:
   char* data_;
   char* cur_; // Points to current Record
   int cur_record_num_;
   Record cur_record_; // Filled in with current Record info

   uint16_t id_;
   uint16_t flags_;
   uint16_t answer_rrs_;
   uint16_t authority_rrs_;
   uint16_t additional_rrs_;
};
