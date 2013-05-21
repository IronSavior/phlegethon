#ifndef _GUARD_TRACKER_H_
#define _GUARD_TRACKER_H_
#pragma once

#ifdef _WIN32
  #include <boost/thread/mutex.hpp>
#else
  #include <mutex>
#endif

#include <boost/signals2/connection.hpp>
#include "stats.h"

namespace libpcap {
  struct packet_t;
  class live_capture; 
}

namespace Stats {
  class Tracker {
    #ifdef _WIN32
      using mutex_t = boost::mutex;
      using lock_guard_t = boost::mutex::scoped_lock;
    #else
      using mutex_t = std::mutex;
      using lock_guard_t = std::lock_guard<std::mutex>;
    #endif
    
    peer_data_t peer_data;
    boost::signals2::scoped_connection pcap_conn;
    mutex_t mtx;
    void expire_samples();
    void update( const peer_spec_t& peer_spec, const libpcap::packet_t& packet );
  public:
    Tracker( libpcap::live_capture& pcap, const duration& datapoint_period, const duration& quantum_period );
    void on_packet( uint8_t* user, const libpcap::packet_t& packet );
    peer_data_t snapshot();
  };
}

#endif
