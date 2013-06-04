#ifndef _GUARD_NET_BYTE_ORDER_H_
#define _GUARD_NET_BYTE_ORDER_H_
#pragma once

#include <cstdint>

namespace net {

  uint16_t ntoh( const uint16_t& src );
  uint32_t ntoh( const uint32_t& src );
  
  uint16_t hton( const uint16_t& src );
  uint32_t hton( const uint32_t& src );

}

#endif
