#include <string>
#include <cstdint>
#include <boost/signals2.hpp>

#include "pcap_c.h"
#include "libpcap.h"

namespace libpcap {

void global_pcap_handler( uint8_t* user, const pcap_pkthdr* header, const uint8_t* packet );
  
interface_list_t interfaces() {
  interface_list_t list;

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *all;
  if( pcap_findalldevs(&all, errbuf) == -1 ) {
    // TODO:  should throw or something
    return list;
  }

  for( auto dev = all; dev != NULL; dev = dev->next ) {
    list.push_back(
      interface_t{
        dev->name,
        dev->description? dev->description : ""
      }
    );
  }

  pcap_freealldevs(all);
  return list;
}
  
void live_capture::capture_loop( uint8_t* user ) {
  if( pcap && !_error ) {
    user_data = user;
    pcap_loop(pcap, -1, global_pcap_handler, (uint8_t*)this);
  }
  // TODO:  Maybe this should throw in case of _error or !pcap
}

boost::signals2::connection live_capture::packet_handler( packet_event_slot_t slot ) {
  return packet_event.connect(slot);
}

bool live_capture::has_error() {
  return _error;
}

std::string live_capture::get_error() {
  return err_msg;
}

unsigned long live_capture::dropped_count() {
  // TODO:  Should handle _error or !pcap state
  pcap_stat stats;
  pcap_stats(pcap, &stats);
  return stats.ps_drop;
}

live_capture::live_capture( std::string interface, std::string filter, int cap_timeout, bool promisc , int snaplen )
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

live_capture::~live_capture() {
  if( pcap ) pcap_close(pcap);
  pcap = nullptr;
}

interface_t::interface_t( std::string name, std::string description )
  : name(name),
    description(description)
{}

packet_t::packet_t( const clock::time_point& time, const size_t len, const size_t caplen, const uint8_t* raw_packet )
  : time(time),
    size(len),
    data(raw_packet, raw_packet + caplen)
{}

void global_pcap_handler( uint8_t* user, const pcap_pkthdr* header, const uint8_t* packet ) {
  using std::chrono::seconds;
  using std::chrono::microseconds;
  
  auto _packet = packet_t(
    clock::time_point(seconds(header->ts.tv_sec) + microseconds(header->ts.tv_usec)),
    header->len,
    header->caplen,
    packet
  );
  
  auto pcap = (live_capture*)user;
  pcap->packet_event(pcap->user_data, _packet);
}

} // namespace Pcap
