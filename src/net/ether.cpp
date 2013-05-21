#include "ether.h"

// For ntohX / htonX
#ifdef _WIN32
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif

namespace net {
namespace ether {

void header_t::ntoh() {
  type = ntohs(type);
}

header_t header_t::load( std::istream& is, bool ntoh ) {
  header_t h;
  is.read((char*)&h.src_addr, sizeof(h.src_addr));
  is.read((char*)&h.dst_addr, sizeof(h.dst_addr));
  is.read((char*)&h.type,     sizeof(h.type));
  if( ntoh ) h.ntoh();
  return h;
}

std::string to_string( const addr_t& addr, const style_t& style ) {
  // TODO:  Implementation!
  return std::string();
}

}} // namespace net::ether
