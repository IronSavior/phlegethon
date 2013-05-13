#ifndef _GUARD_LIBPCAP_H_
#define _GUARD_LIBPCAP_H_
#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <chrono>
#include <boost/signals2.hpp>

struct pcap;
typedef pcap pcap_t;
struct pcap_pkthdr;

namespace libpcap {
  using clock = std::chrono::high_resolution_clock;
  
  struct interface_t {
    std::string name;
    std::string description;
    interface_t( std::string name, std::string description );
  };
  using interface_list_t = std::vector<interface_t>;
  interface_list_t interfaces();
  
  struct packet_t {
    using data_t = std::vector<uint8_t>;
    const clock::time_point time;
    const size_t size;
    const data_t data;
    packet_t( const clock::time_point& time, const size_t len, const size_t caplen, const uint8_t* raw_packet );
  };
  
  using packet_event_signature = void (uint8_t* user, const packet_t& packet );
  using packet_event_signal_t  = boost::signals2::signal<packet_event_signature>;

  class live_capture {
    friend void global_pcap_handler( uint8_t* user, const pcap_pkthdr* header, const uint8_t* packet );
    packet_event_signal_t packet_event;
    
    std::string interface;
    std::string filter;
    std::string err_msg;
    bool        _error;
    uint8_t*    user_data;
    pcap_t*     pcap;
    
  public:
    static const int DEFAULT_SNAPLEN = 1024;
    using packet_event_slot_t = packet_event_signal_t::slot_type;
    
    void capture_loop( uint8_t* user = nullptr );
    boost::signals2::connection packet_handler( packet_event_slot_t slot );
    bool has_error();
    std::string get_error();
    unsigned long dropped_count();
    
    live_capture( std::string interface, std::string filter, int cap_timeout, bool promisc = true, int snaplen = DEFAULT_SNAPLEN );
    ~live_capture();
  };
}

#endif
