#include <sstream>
#include "ip.h"

// For ntohX / htonX
#ifdef _WIN32
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif

namespace net {
namespace ip {

uint8_t header_t::version() {
  return (ver_ihl & 0xF0) >> 4;
}

uint8_t header_t::ihl() {
  return (ver_ihl & 0x0F);
}

size_t header_t::size() {
  return ihl() * sizeof(uint32_t);
}

bool header_t::has_options() {
  static const int IHL_WITHOUT_OPTIONS = 5;
  return ihl() > IHL_WITHOUT_OPTIONS;
}

void header_t::ntoh() {
  total_length = ntohs(total_length);
  id           = ntohs(id);
  flags_fo     = ntohs(flags_fo);
  checksum     = ntohs(checksum);
  src_addr     = ntohl(src_addr);
  dst_addr     = ntohl(dst_addr);
}

header_t header_t::load( std::istream& is, bool ntoh ) {
  header_t h;
  is.read((char*)&h.ver_ihl,      sizeof(h.ver_ihl));
  is.read((char*)&h.tos,          sizeof(h.tos));
  is.read((char*)&h.total_length, sizeof(h.total_length));
  is.read((char*)&h.id,           sizeof(h.id));
  is.read((char*)&h.flags_fo,     sizeof(h.flags_fo));
  is.read((char*)&h.ttl,          sizeof(h.ttl));
  is.read((char*)&h.protocol,     sizeof(h.protocol));
  is.read((char*)&h.checksum,     sizeof(h.checksum));
  is.read((char*)&h.src_addr,     sizeof(h.src_addr));
  is.read((char*)&h.dst_addr,     sizeof(h.dst_addr));
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
  addr_t a = htonl(addr.addr);
  std::ostringstream s;
  s << (int)a.octet[0] << ".";
  s << (int)a.octet[1] << ".";
  s << (int)a.octet[2] << ".";
  s << (int)a.octet[3];
  return s.str();
}

std::ostream& operator<<( std::ostream& stream, const addr_t& addr ) {
  return stream << to_string(addr);
}

}} // namespace net::ip
