#ifndef _GUARD_NET_H_
#define _GUARD_NET_H_
#pragma once

#include <cstdint>
#include <string>

namespace Net {
  using addr_t = uint32_t;
  using port_t = uint16_t;
  
  template< typename T > T load( std::istream& stream, bool ntoh = true );

  struct ether_header_t {
    uint8_t  dst_addr[6];
    uint8_t  src_addr[6];
    uint16_t type;
    static const int TYPE_IP = 0x0800;
  };
  template<> ether_header_t load( std::istream& stream, bool ntoh );

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
    
    uint8_t version();
    uint8_t ihl();
    size_t size();
    bool has_options();
    static const int IHL_NO_OPTIONS = 5;
    static const int PROTO_UDP = 17;
  };
  template<> ip_header_t  load( std::istream& stream, bool ntoh );
  
  struct udp_header_t {
    port_t   src_port;
    port_t   dst_port;
    uint16_t length;
    uint16_t checksum;
  };
  template<> udp_header_t load( std::istream& stream, bool ntoh );
  
  std::string to_string( const addr_t& addr );
}

#endif
