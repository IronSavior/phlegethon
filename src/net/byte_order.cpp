// For ntohX / htonX
#ifdef _WIN32
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif

#include "byte_order.h"

namespace net {

uint16_t ntoh( const uint16_t& src ) {
  return ntohs(src);
}

uint32_t ntoh( const uint32_t& src ) {
  return ntohl(src);
}

uint16_t hton( const uint16_t& src ) {
  return htons(src);
}

uint32_t hton( const uint32_t& src ) {
  return htonl(src);
}

} // namespace net
