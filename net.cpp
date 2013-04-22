#include <string>
#include <sstream>
#include <cstdint>

#include "net.h"

// For ntohX / htonX
#ifdef _WIN32
  extern "C" {
    #include <winsock2.h>
  }
#else
  extern "C" {
    #include <arpa/inet.h>
  }
#endif

namespace Net {
  
ip_header_t::ip_header_t( const ip_header_t& src, const bool ntoh )
  : ver_ihl(src.ver_ihl),
    tos(src.tos),
    ttl(src.ttl),
    protocol(src.protocol) {
  total_length = ntoh? ntohs(src.total_length) : src.total_length;
  id           = ntoh? ntohs(src.id)           : src.id;
  flags_fo     = ntoh? ntohs(src.flags_fo)     : src.flags_fo;
  checksum     = ntoh? ntohs(src.checksum)     : src.checksum;
  src_addr     = ntoh? ntohl(src.src_addr)     : src.src_addr;
  dst_addr     = ntoh? ntohl(src.dst_addr)     : src.dst_addr;
}

uint8_t ip_header_t::version() {
  return (ver_ihl & 0xF0) >> 4;
}

uint8_t ip_header_t::ihl() {
  return (ver_ihl & 0x0F);
}

size_t ip_header_t::size() {
  return ihl() * sizeof(uint32_t);
}

udp_header_t::udp_header_t( const udp_header_t& src, const bool ntoh ) {
  src_port = ntoh? ntohs(src.src_port) : src.src_port;
  dst_port = ntoh? ntohs(src.dst_port) : src.dst_port;
  length   = ntoh? ntohs(src.length)   : src.length;
  checksum = ntoh? ntohs(src.checksum) : src.checksum;
}

std::string to_string( const addr_t& addr ) {
  auto addr_ = htonl(addr);
  auto octet = (uint8_t*)&addr_;
  std::ostringstream s;
  s << (unsigned int)octet[0] << ".";
  s << (unsigned int)octet[1] << ".";
  s << (unsigned int)octet[2] << ".";
  s << (unsigned int)octet[3];
  return s.str();
}

} // namespace Net
