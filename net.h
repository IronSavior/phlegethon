#ifndef _GUARD_NET_H_
#define _GUARD_NET_H_

#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstdint>
#include <string>

namespace Net {
  using addr_t = ::in_addr_t;
  using port_t = ::in_port_t;
  
  #pragma pack(push, 1)
  struct ether_header_t {
    uint8_t  dst_addr[6];
    uint8_t  src_addr[6];
    uint16_t llc_len;
  };
  #pragma pack(pop)
  
  #pragma pack(push, 1)
  struct ip_header_t {
    uint8_t  ver_ihl;  // 4 bits version and 4 bits internet header length
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fo; // 3 bits flags and 13 bits fragment-offset
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    addr_t   src_addr;
    addr_t   dst_addr;
    
    uint8_t version() {
      return (ver_ihl & 0xF0) >> 4;
    };
    
    uint8_t ihl() {
      return (ver_ihl & 0x0F);
    };
    
    size_t size() {
      return ihl() * sizeof(uint32_t);
    };
    
    ip_header_t( const ip_header_t& src, const bool ntoh = false )
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
    };
  };
  #pragma pack(pop)
  
  #pragma pack(push, 1)
  class udp_header_t {
  public:
    port_t   src_port;
    port_t   dst_port;
    uint16_t length;
    uint16_t checksum;
    
    udp_header_t( const udp_header_t& src, const bool ntoh = false ) {
      src_port = ntoh? ntohs(src.src_port) : src.src_port;
      dst_port = ntoh? ntohs(src.dst_port) : src.dst_port;
      length   = ntoh? ntohs(src.length)   : src.length;
      checksum = ntoh? ntohs(src.checksum) : src.checksum;
    };
  };
  #pragma pack(pop)
  
  inline std::string to_string( const in_addr_t& addr ) {
    char buf[INET_ADDRSTRLEN] = "";
    addr_t n = htonl(addr);
    if( inet_ntop(AF_INET, &n, buf, INET_ADDRSTRLEN) != buf ) {
      return std::string();
    }
    return std::string(buf);
  }
}

#endif
