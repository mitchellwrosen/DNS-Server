#ifndef _DEBUG_H_
#define _DEBUG_H_

// For system calls that set errno and return non-zero on error
#define SYSCALL(call, msg); {\
   if (call < 0) {\
      perror(msg);\
      exit(EXIT_FAILURE);\
   }\
}

// For system calls that set errno and return non-zero on error
// Allows cleanup of one file descriptor
#define SYSCALL_FD1(call, fd, msg); {\
   if (call < 0) {\
      perror(msg);\
      close(fd);\
      exit(EXIT_FAILURE);\
   }\
}

#define LOGGING true

#define LOG0(str); {\
   if (LOGGING)\
      std::cout << str << std::endl;\
}

#define LOG1(str, arg1); {\
   if (LOGGING)\
      std::cout << str << arg1 << std::endl;\
}

#endif   // _DEBUG_H_
