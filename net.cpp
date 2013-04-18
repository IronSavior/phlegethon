#include <string>
#include <cstdint>

#include "net.h"

extern "C" {
  #include <arpa/inet.h>
}

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
  char buf[INET_ADDRSTRLEN] = "";
  addr_t n = htonl(addr);
  if( inet_ntop(AF_INET, &n, buf, INET_ADDRSTRLEN) != buf ) {
    return std::string();
  }
  return std::string(buf);
}

} // namespace Net
