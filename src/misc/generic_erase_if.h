#ifndef _GUARD_GENERIC_ERASE_IF_H_
#define _GUARD_GENERIC_ERASE_IF_H_
#pragma once

namespace generic {
  template< typename ContainerT, typename PredicateT >
  void erase_if( ContainerT& items, const PredicateT& predicate ) {
    for( auto it = items.begin(); it != items.end(); ) {
      if( predicate(*it) ) it = items.erase(it);
      else ++it;
    }
  };
}

#endif
