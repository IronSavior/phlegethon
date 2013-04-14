#ifndef _GUARD_PCAP_MANAGER_H_
#define _GUARD_PCAP_MANAGER_H_

#include <pcap.h>
#include <string>
#include <boost/signals2.hpp>

static void global_pcap_handler( uint8_t *user, const pcap_pkthdr* header, const uint8_t* packet );
  
namespace Pcap {
  using packet_event_signature = void (uint8_t *user, const pcap_pkthdr* header, const uint8_t* packet);
  using packet_event_signal_t  = boost::signals2::signal<packet_event_signature>;
  
  class PcapManager {
    friend void ::global_pcap_handler( uint8_t *user, const pcap_pkthdr* header, const uint8_t* packet );
    
    packet_event_signal_t packet_event;
    
    bpf_program filter_program;
    bpf_u_int32 net_mask;
    bpf_u_int32 network;
    std::string interface;
    std::string filter;
    std::string err_msg;
    bool        _error;
    char        errbuf[PCAP_ERRBUF_SIZE];
    uint8_t*    user_data;
    pcap_t*     pcap;
    
  public:
    using packet_event_slot_t = packet_event_signal_t::slot_type;
    
    void capture_loop( uint8_t* user = nullptr ) {
      if( pcap ) {
        user_data = user;
        pcap_loop(pcap, -1, global_pcap_handler, (uint8_t*)this);
      }
    };
    
    boost::signals2::connection packet_handler( packet_event_slot_t slot ) {
      return packet_event.connect(slot);
    };
    
    bool has_error() {
      return _error;
    };
    
    std::string get_error() {
      if( err_msg.empty() ) {
        return std::string(errbuf);
      }
      return err_msg;
    };
    
    pcap_stat stats() {
      pcap_stat stat;
      pcap_stats(pcap, &stat);
      return stat;
    }
    
    PcapManager( std::string interface, std::string filter, int cap_timeout, bool promisc = true, int snaplen = 1024 )
      : interface(interface),
        filter(filter),
        _error(false),
        user_data(nullptr),
        pcap(nullptr) {
      errbuf[0] = '\0';
      pcap_lookupnet(interface.c_str(), &network, &net_mask, errbuf);
      pcap = pcap_open_live(interface.c_str(), snaplen, promisc, cap_timeout, errbuf);
      if( pcap == NULL ) {
        _error = true;
        return;
      }
      
      if( pcap_compile(pcap, &filter_program, filter.c_str(), false, network) == -1 ) {
        _error = true;
        err_msg = "Bad filter - check host and port";
        return;
      }
      
      if( pcap_setfilter(pcap, &filter_program) == -1 ) {
        _error = true;
        err_msg = "Error while attaching filter";
        return;
      }
    };
    
    ~PcapManager() {
      if( pcap ) {
        pcap_close(pcap);
        pcap = nullptr;
      }
    };
  };
}

static void global_pcap_handler( uint8_t *user, const pcap_pkthdr* header, const uint8_t* packet ) {
  auto pcap = (Pcap::PcapManager*)user;
  pcap->packet_event(pcap->user_data, header, packet);
}
#endif
