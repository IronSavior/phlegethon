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

uint8_t ip_header_t::version() {
  return (ver_ihl & 0xF0) >> 4;
}

uint8_t ip_header_t::ihl() {
  return (ver_ihl & 0x0F);
}

size_t ip_header_t::size() {
  return ihl() * sizeof(uint32_t);
}

bool ip_header_t::has_options() {
  return ihl() > IHL_NO_OPTIONS;
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

template<>
ip_header_t load( std::istream& stream, bool ntoh ) {
  ip_header_t header;
  stream.read((char*)&header.ver_ihl,      sizeof(header.ver_ihl));
  stream.read((char*)&header.tos,          sizeof(header.tos));
  stream.read((char*)&header.total_length, sizeof(header.total_length));
  stream.read((char*)&header.id,           sizeof(header.id));
  stream.read((char*)&header.flags_fo,     sizeof(header.flags_fo));
  stream.read((char*)&header.ttl,          sizeof(header.ttl));
  stream.read((char*)&header.protocol,     sizeof(header.protocol));
  stream.read((char*)&header.checksum,     sizeof(header.checksum));
  stream.read((char*)&header.src_addr,     sizeof(header.src_addr));
  stream.read((char*)&header.dst_addr,     sizeof(header.dst_addr));
  if( ntoh ) {
    header.total_length = ntohs(header.total_length);
    header.id =           ntohs(header.id);
    header.flags_fo =     ntohs(header.flags_fo);
    header.checksum =     ntohs(header.checksum);
    header.src_addr =     ntohl(header.src_addr);
    header.dst_addr =     ntohl(header.dst_addr);
  }
  return header;
}

template<>
udp_header_t load( std::istream& stream, bool ntoh ) {
  udp_header_t header;
  stream.read((char*)&header.src_port, sizeof(header.src_port));
  stream.read((char*)&header.dst_port, sizeof(header.dst_port));
  stream.read((char*)&header.length,   sizeof(header.length));
  stream.read((char*)&header.checksum, sizeof(header.checksum));
  if( ntoh ) {
    header.src_port = ntohs(header.src_port);
    header.dst_port = ntohs(header.dst_port);
    header.length   = ntohs(header.length);
    header.checksum = ntohs(header.checksum);
  }
  return header;
}

template<>
ether_header_t load( std::istream& stream, bool ntoh ) {
  ether_header_t header;
  stream.read((char*)&header.src_addr, sizeof(header.src_addr));
  stream.read((char*)&header.dst_addr, sizeof(header.dst_addr));
  stream.read((char*)&header.type,     sizeof(header.type));
  if( ntoh ) {
    header.type = ntohs(header.type);
  }
  return header;
}

} // namespace Net
