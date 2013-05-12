#ifndef _GUARD_B_SLEEP_FOR_H_
#define _GUARD_B_SLEEP_FOR_H_
#pragma once

#include <chrono>
#include <boost/chrono.hpp>
#include <boost/thread.hpp>

namespace boost { namespace this_thread {
  // Allow boost::this_thread::sleep_for to accept std::chrono::duration
  template< class Rep, class Period >
  void sleep_for( const std::chrono::duration<Rep, Period>& d ) {
    using chrono::steady_clock;
    using chrono::duration;
    using chrono::nanoseconds;
    using chrono::ceil;
    using _Period = ratio<Period::num, Period::den>;
    auto _d = duration<Rep, _Period>(d.count());
    auto wake_time = steady_clock::time_point(steady_clock::now() + ceil<nanoseconds>(_d));
    sleep_until(wake_time);
  }
}}

#endif
