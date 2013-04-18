#ifndef _GUARD_STATS_H_
#define _GUARD_STATS_H_

#include <string>
#include <map>
#include <chrono>
#include <cstdint>
#include <boost/circular_buffer.hpp>
#include <boost/thread.hpp>
#include <boost/signals2/connection.hpp>

#include "net.h"
#include "pcap_manager.h"

class pcap_pkthdr;

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
  
  class Tracker {
    peer_data_t peer_data;
    boost::signals2::scoped_connection pcap_conn;
    boost::mutex mtx;
    void cleanup();
  public:
    void on_packet( uint8_t* user, const pcap_pkthdr* header, const uint8_t* packet );
    peer_data_t snapshot();
    
    Tracker( Pcap::PcapManager& pcap, const duration datapoint_period, const duration quantum_period );
  };
}
#endif
