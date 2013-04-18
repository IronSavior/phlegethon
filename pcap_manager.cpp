#include <string>
#include <cstdint>
#include <boost/signals2.hpp>

#include "pcap_manager.h"

extern "C" {
  #include <pcap.h>
}

namespace Pcap {
  
void PcapManager::capture_loop( uint8_t* user ) {
  if( pcap ) {
    user_data = user;
    pcap_loop(pcap, -1, global_pcap_handler, (uint8_t*)this);
  }
}

boost::signals2::connection PcapManager::packet_handler( packet_event_slot_t slot ) {
  return packet_event.connect(slot);
}

bool PcapManager::has_error() {
  return _error;
}

std::string PcapManager::get_error() {
  return err_msg;
}

unsigned long PcapManager::dropped_count() {
  pcap_stat stats;
  pcap_stats(pcap, &stats);
  return stats.ps_drop;
}

PcapManager::PcapManager( std::string interface, std::string filter, int cap_timeout, bool promisc , int snaplen )
  : interface(interface),
    filter(filter),
    _error(false),
    user_data(nullptr),
    pcap(nullptr) {
  uint32_t net_mask = 0;
  uint32_t network = 0;
  char errbuf[PCAP_ERRBUF_SIZE] = {'\0'};
  
  if( 0 != pcap_lookupnet(interface.c_str(), &network, &net_mask, errbuf) ) {
    err_msg = std::string(errbuf);
    _error = true;
    return;
  }
  
  pcap = pcap_open_live(interface.c_str(), snaplen, promisc, cap_timeout, errbuf);
  if( pcap == NULL ) {
    err_msg = std::string(errbuf);
    _error = true;
    return;
  }
  
  bpf_program filter_program;
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
}

PcapManager::~PcapManager() {
  if( pcap ) pcap_close(pcap);
  pcap = nullptr;
}

void global_pcap_handler( uint8_t *user, const pcap_pkthdr* header, const uint8_t* packet ) {
  auto pcap = (PcapManager*)user;
  pcap->packet_event(pcap->user_data, header, packet);
};

} // namespace Pcap
