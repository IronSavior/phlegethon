#ifndef _GUARD_TRACKER_H_
#define _GUARD_TRACKER_H_
#pragma once

#include <boost/thread/mutex.hpp>
#include <boost/signals2/connection.hpp>
#include "stats.h"

namespace libpcap {
  struct packet_header_t;
  class live_capture; 
}

namespace Stats {
  class Tracker {
    peer_data_t peer_data;
    boost::signals2::scoped_connection pcap_conn;
    boost::mutex mtx;
    void cleanup();
  public:
    void on_packet( uint8_t* user, const libpcap::packet_header_t& header, const uint8_t* packet );
    peer_data_t snapshot();
    
    Tracker( libpcap::live_capture& pcap, const duration datapoint_period, const duration quantum_period );
  };
}

#endif
