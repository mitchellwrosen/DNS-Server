
class DNSServer : UDPServer {
  public:
   DNSServer();
   void Run();
  private:
   const std::string port_;
}
