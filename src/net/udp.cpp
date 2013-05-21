#include "udp.h"

// For ntohX / htonX
#ifdef _WIN32
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif

namespace net {
namespace udp {

void header_t::ntoh() {
  src_port = ntohs(src_port);
  dst_port = ntohs(dst_port);
  length   = ntohs(length);
  checksum = ntohs(checksum);
}

header_t header_t::load( std::istream& is, bool ntoh ) {
  header_t h;
  is.read((char*)&h.src_port, sizeof(h.src_port));
  is.read((char*)&h.dst_port, sizeof(h.dst_port));
  is.read((char*)&h.length,   sizeof(h.length));
  is.read((char*)&h.checksum, sizeof(h.checksum));
  if( ntoh ) h.ntoh();
  return h;
}

}} // namespace net::udp
