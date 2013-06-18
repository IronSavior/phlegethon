#include "generic_read.h"
#include "byte_order.h"
#include "udp.h"

namespace net {
namespace udp {

void header_t::ntoh() {
  using net::ntoh;
  src_port = ntoh(src_port);
  dst_port = ntoh(dst_port);
  length   = ntoh(length);
  checksum = ntoh(checksum);
}

header_t header_t::load( std::istream& is, bool ntoh ) {
  using generic::read;
  header_t h;
  read(is, h.src_port);
  read(is, h.dst_port);
  read(is, h.length);
  read(is, h.checksum);
  if( ntoh ) h.ntoh();
  return h;
}

}} // namespace net::udp
