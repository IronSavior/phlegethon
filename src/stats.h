#ifndef _GUARD_STATS_H_
#define _GUARD_STATS_H_
#pragma once

#include <string>
#include <map>
#include <chrono>
#include <cstdint>
#include <boost/circular_buffer.hpp>

#include "net.h"

namespace Stats {
  using clock  = std::chrono::system_clock;
  using duration = clock::duration;
  using addr_t = Net::addr_t;
  using port_t = Net::port_t;
  
  struct peer_spec_t {
    addr_t addr;
    port_t port;
    
    peer_spec_t();
    peer_spec_t( const addr_t addr, const port_t port );
    bool operator <( const peer_spec_t& rhs ) const;
  };
  
  struct sample_t {
    clock::time_point start_time;
    size_t packets, bytes;
    
    sample_t();
    sample_t( const clock::time_point start );
  };

  using data_point_t = boost::circular_buffer<sample_t>;
  using peer_data_map_t = std::map<peer_spec_t, data_point_t>;
    
  class peer_data_t : public peer_data_map_t {
  public:
    const duration datapoint_period;
    const duration quantum_period;
    const int samples_per_dp;
    
    peer_data_t( const duration datapoint_period, const duration quantum_period );
  };

  template< typename ContainerT, typename PredicateT >
  void erase_if( ContainerT& items, const PredicateT& predicate ) {
    for( auto it = items.begin(); it != items.end(); ) {
      if( predicate(*it) ) it = items.erase(it);
      else ++it;
    }
  };

}
#endif
