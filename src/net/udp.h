#ifndef _GUARD_NET_UDP_H_
#define _GUARD_NET_UDP_H_
#pragma once

#include <cstdint>
#include <istream>

namespace net {
namespace udp {
  
  using port_t = uint16_t;
  
  struct header_t {
    port_t   src_port;
    port_t   dst_port;
    uint16_t length;
    uint16_t checksum;
    
    static header_t load( std::istream& is, bool ntoh = true );
  private:
    void _ntoh();
  };
  
}} // namespace net::udp

#endif
