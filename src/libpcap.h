#ifndef _GUARD_LIBPCAP_H_
#define _GUARD_LIBPCAP_H_
#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <boost/signals2.hpp>

struct pcap;
typedef pcap pcap_t;
struct pcap_pkthdr;

namespace libpcap {
  struct interface_t {
    std::string name;
    std::string description;
    interface_t( std::string name, std::string description );
  };
  using interface_list_t = std::vector<interface_t>;
  interface_list_t interfaces();
  
  using clock = std::chrono::high_resolution_clock;
  struct packet_header_t {
    clock::time_point time;
    size_t len, cap_len;
    packet_header_t( const clock::time_point& time, const size_t len, const size_t caplen );
  };
  
  using packet_event_signature = void (uint8_t* user, const packet_header_t& header, const uint8_t* packet);
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
    using packet_event_slot_t = packet_event_signal_t::slot_type;
    
    void capture_loop( uint8_t* user = nullptr );
    boost::signals2::connection packet_handler( packet_event_slot_t slot );
    bool has_error();
    std::string get_error();
    unsigned long dropped_count();
    
    live_capture( std::string interface, std::string filter, int cap_timeout, bool promisc = true, int snaplen = 1024 );
    ~live_capture();
  };
}
#endif
