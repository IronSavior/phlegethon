#ifndef _GUARD_NET_H_
#define _GUARD_NET_H_

#include <cstdint>
#include <string>

namespace Net {
  using addr_t = uint32_t;
  using port_t = uint16_t;
  
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
    
    ip_header_t( const ip_header_t& src, const bool ntoh = false );
    uint8_t version();
    uint8_t ihl();
    size_t size();
  };
  #pragma pack(pop)
  
  #pragma pack(push, 1)
  class udp_header_t {
  public:
    port_t   src_port;
    port_t   dst_port;
    uint16_t length;
    uint16_t checksum;
    
    udp_header_t( const udp_header_t& src, const bool ntoh = false );
  };
  #pragma pack(pop)
  
  std::string to_string( const addr_t& addr );
}

#endif
