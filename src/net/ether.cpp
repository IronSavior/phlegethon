#include "generic_read.h"
#include "byte_order.h"
#include "ether.h"

namespace net {
namespace ether {

header_t header_t::load( std::istream& is, bool _ntoh ) {
  using generic::read;
  header_t h;
  read(is, h.src_addr);
  read(is, h.dst_addr);
  read(is, h.type);
  if( _ntoh ) h.type = ntoh(h.type);
  return h;
}

std::string to_string( const addr_t& addr, const style_t& style ) {
  // TODO:  Implementation!
  return std::string();
}

}} // namespace net::ether
