#ifndef _GUARD_NET_ETHER_H_
#define _GUARD_NET_ETHER_H_
#pragma once

#include <cstdint>
#include <istream>
#include <string>

namespace net {
namespace ether {
  
  struct addr_t {
    union {
      uint16_t word[3];
      uint8_t octet[6];
    };
  };
  
  const uint16_t type_ip = 0x0800;
  
  struct header_t {
    addr_t dst_addr;
    addr_t src_addr;
    uint16_t type;
    
    static header_t load( std::istream& is, bool ntoh = true );
  };

  enum class style_t {
    bytes,
    words
  };
  
  std::string to_string( const addr_t& addr, const style_t& style = style_t::bytes );

}} // namespace net::ether

#endif
