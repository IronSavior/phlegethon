#include <sstream>
#include "generic_read.h"
#include "byte_order.h"
#include "ip.h"

namespace net {
namespace ip {

uint8_t header_t::version() {
  return (ver_ihl & 0xF0) >> 4;
}

uint8_t header_t::ihl() {
  return ver_ihl & 0x0F;
}

size_t header_t::size() {
  return ihl() * sizeof(uint32_t);
}

bool header_t::has_options() {
  static const int IHL_WITHOUT_OPTIONS = 5;
  return ihl() > IHL_WITHOUT_OPTIONS;
}

void header_t::ntoh() {
  using net::ntoh;
  total_length = ntoh(total_length);
  id           = ntoh(id);
  flags_fo     = ntoh(flags_fo);
  checksum     = ntoh(checksum);
  src_addr     = ntoh(src_addr);
  dst_addr     = ntoh(dst_addr);
}

header_t header_t::load( std::istream& is, bool ntoh ) {
  using generic::read;
  header_t h;
  read(is, h.ver_ihl);
  read(is, h.tos);
  read(is, h.total_length);
  read(is, h.id);
  read(is, h.flags_fo);
  read(is, h.ttl);
  read(is, h.protocol);
  read(is, h.checksum);
  read(is, h.src_addr);
  read(is, h.dst_addr);
  if( ntoh ) h.ntoh();
  return h;
}

addr_t::addr_t()
  : addr(0)
{}

addr_t::addr_t( const uint32_t& addr )
  : addr(addr)
{}

addr_t::operator uint32_t() {
  return addr;
}

bool addr_t::operator<( const addr_t& rhs ) const {
  return addr < rhs.addr;
}

bool addr_t::operator==( const addr_t& rhs ) const {
  return addr == rhs.addr;
}

std::string to_string( const addr_t& addr ) {
  addr_t a = hton(addr.addr);
  std::ostringstream s;
  s << static_cast<int>(a.octet[0]) << ".";
  s << static_cast<int>(a.octet[1]) << ".";
  s << static_cast<int>(a.octet[2]) << ".";
  s << static_cast<int>(a.octet[3]);
  return s.str();
}

std::ostream& operator<<( std::ostream& stream, const addr_t& addr ) {
  return stream << to_string(addr);
}

}} // namespace net::ip
