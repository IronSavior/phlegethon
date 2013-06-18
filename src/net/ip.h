#ifndef _GUARD_NET_IP_H_
#define _GUARD_NET_IP_H_
#pragma once

#include <cstdint>
#include <istream>
#include <ostream>
#include <string>

namespace net {
namespace ip {
  
  struct addr_t {
    union {
      uint32_t addr;
      uint8_t  octet[4];
    };
    addr_t();
    addr_t( const uint32_t& addr );
    operator uint32_t();
    bool operator<( const addr_t& rhs ) const;
    bool operator==( const addr_t& rhs ) const;
  };
  
  const uint8_t proto_udp = 17;

  struct header_t {
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
    static header_t load( std::istream& is, bool ntoh = true );
  private:
    void ntoh();
  };
  
  std::string to_string( const addr_t& addr );
  std::ostream& operator<<( std::ostream& stream, const addr_t& addr );
  
}} // namespace net::ip

#endif
