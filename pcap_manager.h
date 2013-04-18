#ifndef _GUARD_PCAP_MANAGER_H_
#define _GUARD_PCAP_MANAGER_H_

#include <string>
#include <boost/signals2.hpp>

struct pcap;
typedef pcap pcap_t;
struct pcap_pkthdr;

namespace Pcap {
  using packet_event_signature = void (uint8_t *user, const pcap_pkthdr* header, const uint8_t* packet);
  using packet_event_signal_t  = boost::signals2::signal<packet_event_signature>;
  
  void global_pcap_handler( uint8_t *user, const pcap_pkthdr* header, const uint8_t* packet );
  
  class PcapManager {
    friend void global_pcap_handler( uint8_t *user, const pcap_pkthdr* header, const uint8_t* packet );
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
    
    PcapManager( std::string interface, std::string filter, int cap_timeout, bool promisc = true, int snaplen = 1024 );
    ~PcapManager();
  };
}
#endif
