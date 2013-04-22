#ifndef _GUARD_B_SLEEP_FOR_H_
#define _GUARD_B_SLEEP_FOR_H_

#include <chrono>
#include <boost/thread.hpp>

namespace boost { namespace this_thread {
  template< class Rep, class Period >
  void sleep_for( const std::chrono::duration<Rep, Period>& d ) {
    chrono::system_clock::duration _d(d.count());
    sleep_for(_d);    
  }
}}

#endif
