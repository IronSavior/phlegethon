#include <istream>
#include <sstream>

#include "libpcap.h"
#include "net.h"
#include "tracker.h"

namespace Stats {

namespace arg = std::placeholders;

void Tracker::on_packet( uint8_t* user, const libpcap::packet_t& packet ) {
  using Net::ip_header_t;
  using Net::udp_header_t;
  using Net::ether_header_t;
  using Net::load;
  
  std::istringstream stream(std::string(packet.data.begin(), packet.data.end()));
  
  auto ether_header = load<ether_header_t>(stream);
  if( ether_header.type != ether_header_t::TYPE_IP ) return;

  auto ip_header = load<ip_header_t>(stream);
  if( ip_header.protocol != ip_header_t::PROTO_UDP ) return;
  
  if( ip_header.has_options() ) {
    stream.seekg(sizeof(ether_header_t) + ip_header.size(), std::ios_base::beg);
  }
  auto udp_header = load<udp_header_t>(stream);
  
  update(peer_spec_t(ip_header.dst_addr, udp_header.dst_port), packet);
}

void Tracker::update( const peer_spec_t& peer_spec, const libpcap::packet_t& packet ) {
  lock_guard_t lock(mtx);
  auto peer = peer_data.find(peer_spec);
  if( peer == peer_data.end() ) {
    auto dp = data_point_t(peer_data.samples_per_dp);
    dp.push_back(sample_t(packet.time));
    auto value = std::make_pair(peer_spec, dp);
    peer = peer_data.insert(peer, value);
  }
  
  data_point_t& dp = peer->second;
  if( dp.back().start_time < packet.time - peer_data.quantum_period ) {
    dp.push_back(sample_t(packet.time));
  }
  dp.back().packets += 1;
  dp.back().bytes   += packet.size;
}

void Tracker::expire_samples() {
  using peer_type = peer_data_t::value_type;
  using sample_type = peer_type::second_type::value_type;
  
  const auto deadline = clock::now() - peer_data.datapoint_period;
  erase_if(peer_data, [&deadline]( peer_type& peer ) {
    erase_if(peer.second, [&deadline]( sample_type& sample ) {
      return sample.start_time < deadline;
    });
    return peer.second.size() == 0;
  });
}

peer_data_t Stats::Tracker::snapshot() {
  lock_guard_t lock(mtx);
  expire_samples();
  return peer_data_t(peer_data);
}

Tracker::Tracker( libpcap::live_capture& pcap, const duration datapoint_period, const duration quantum_period )
  : peer_data(datapoint_period, quantum_period),
    pcap_conn(
      pcap.packet_handler(
        std::bind(&Tracker::on_packet, this, arg::_1, arg::_2)
      )
    )
{}

} // namespace Stats
