#ifndef _GUARD_GENERIC_READ_H_
#define _GUARD_GENERIC_READ_H_
#pragma once

#include <istream>
#include <type_traits>

namespace generic {
  
  template< typename T >
  void read( std::istream& is, T& v ) {
    static_assert(std::is_standard_layout<T>::value, "T must be a POD type.");
    is.read(reinterpret_cast<char*>(&v), sizeof(v));
  };

  template< typename T >
  T read( std::istream& is ) {
    static_assert(std::is_standard_layout<T>::value, "Must return a POD type.");
    T v;
    is.read(reinterpret_cast<char*>(&v), sizeof(v));
    return v;
  };

}

#endif
