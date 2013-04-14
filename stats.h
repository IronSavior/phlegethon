#ifndef _GUARD_STATS_H_
#define _GUARD_STATS_H_

#include <string>
#include <map>
#include <chrono>
#include <boost/circular_buffer.hpp>
#include <boost/thread.hpp>
#include <boost/signals2/connection.hpp>
#include <pcap.h>

#include "net.h"
#include "pcap_manager.h"

namespace Stats {
  using clock  = std::chrono::system_clock;
  using addr_t = Net::addr_t;
  using port_t = Net::port_t;
  
  struct peer_spec_t {
    addr_t addr;
    port_t port;
    peer_spec_t() : addr(0), port(0) {};
    peer_spec_t( const addr_t addr, const port_t port ) : addr(addr), port(port) {};
    bool operator<( const peer_spec_t& rhs ) const {
      if( addr == rhs.addr ) {
        return port < rhs.port;
      }
      return addr < rhs.addr;
    };
  };
  
  struct sample_t {
    using time_point = clock::time_point;
    time_point start_time;
    size_t     packets, bytes;
    sample_t() : packets(0), bytes(0) {};
    sample_t( const time_point start ) : start_time(start), packets(0), bytes(0) {};
  };

  using data_point_t = boost::circular_buffer<sample_t>;
  using peer_data_map_t = std::map<peer_spec_t, data_point_t>;
  
  class peer_data_t : public peer_data_map_t {
  public:
    const clock::duration datapoint_period;
    const clock::duration quantum_period;
    const int samples_per_dp;
    
    peer_data_t( const clock::duration datapoint_period, const clock::duration quantum_period )
      : peer_data_map_t(),
        datapoint_period(datapoint_period),
        quantum_period(quantum_period),
        samples_per_dp(datapoint_period / quantum_period)
    {};
  };
  
  class Tracker {
    peer_data_t peer_data;
    boost::signals2::scoped_connection pcap_conn;
    boost::mutex mtx;
    void cleanup();
  public:
    void on_packet( uint8_t* user, const pcap_pkthdr* header, const uint8_t* packet );
    peer_data_t snapshot();
    
    Tracker( Pcap::PcapManager& pcap, const clock::duration datapoint_period, const clock::duration quantum_period )
      : peer_data(datapoint_period, quantum_period),
        pcap_conn(
          pcap.packet_handler(
            std::bind(&Tracker::on_packet, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)
          )
        )
    {};
  };
}
#endif
