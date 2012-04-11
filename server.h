
class Server {
  public:
   virtual void Run() = 0;
  protected:
   // Initialize server (get sock, bind, listen)
   Init(const std::string port, struct addrinfo* hints);

   int sock_;
   int backlog_;
}
