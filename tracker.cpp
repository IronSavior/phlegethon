#include <iostream>
#include <sstream>
#include <boost/thread.hpp>

#include "libpcap.h"
#include "net.h"
#include "stats.h"

namespace Stats {

void Tracker::on_packet( uint8_t* user, const pcap_pkthdr* header, const uint8_t* packet ) {
  using std::chrono::seconds;
  using std::chrono::microseconds;
  using Net::ip_header_t;
  using Net::udp_header_t;
  using Net::ether_header_t;
  
  auto packet_time = clock::time_point(seconds(header->ts.tv_sec) + microseconds(header->ts.tv_usec));
  auto ip_header = ip_header_t((ip_header_t&)*(packet + sizeof(ether_header_t)), true);
  auto udp_header = udp_header_t((udp_header_t&)*(packet + ip_header.size() + sizeof(ether_header_t)), true);
  auto peer_spec = peer_spec_t(ip_header.dst_addr, udp_header.dst_port);
  
  boost::mutex::scoped_lock lock(mtx);
  
  auto peer = peer_data.find(peer_spec);
  if( peer == peer_data.end() ) {
    auto dp = data_point_t(peer_data.samples_per_dp);
    dp.push_back(sample_t(packet_time));
    auto value = std::make_pair(peer_spec, dp);
    peer = peer_data.insert(peer, value);
  }
  
  data_point_t& dp = peer->second;
  if( dp.back().start_time < packet_time - peer_data.quantum_period ) {
    dp.push_back(sample_t(packet_time));
  }
  dp.back().packets += 1;
  dp.back().bytes   += header->len;
}

void Tracker::cleanup() {
  using std::chrono::seconds;
  for( auto peer = peer_data.begin(); peer != peer_data.end(); ) {
    data_point_t& dp = peer->second;
    for( auto sample = dp.begin(); sample != dp.end(); ) {
      if( sample->start_time < (clock::now() - peer_data.datapoint_period) ) {
        sample = dp.erase(sample);
      }
      else { ++sample; }
    }
    if( dp.size() == 0 ) {
      peer = peer_data.erase(peer);
    }
    else { ++peer; }
  }
}

peer_data_t Stats::Tracker::snapshot() {
  boost::mutex::scoped_lock lock(mtx);
  cleanup();
  return peer_data_t(peer_data);
}

namespace arg = std::placeholders;
Tracker::Tracker( Pcap::PcapManager& pcap, const duration datapoint_period, const duration quantum_period )
  : peer_data(datapoint_period, quantum_period),
    pcap_conn(
      pcap.packet_handler(
        std::bind(&Tracker::on_packet, this, arg::_1, arg::_2, arg::_3)
      )
    )
{}

} // namespace Stats
