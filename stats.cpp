#include <functional>
#include "stats.h"

namespace Stats {

namespace arg = std::placeholders;

peer_spec_t::peer_spec_t()
  : addr(0), port(0) {}

peer_spec_t::peer_spec_t( const addr_t addr, const port_t port )
  : addr(addr), port(port) {}
  
bool peer_spec_t::operator <( const peer_spec_t& rhs ) const {
  return (addr == rhs.addr)? port < rhs.port : addr < rhs.addr;
}

sample_t::sample_t()
  : packets(0), bytes(0) {}

sample_t::sample_t( const clock::time_point start )
  : start_time(start), packets(0), bytes(0) {}

peer_data_t::peer_data_t( const duration datapoint_period, const duration quantum_period )
  : peer_data_map_t(),
    datapoint_period(datapoint_period),
    quantum_period(quantum_period),
    samples_per_dp(datapoint_period / quantum_period)
{}

Tracker::Tracker( Pcap::PcapManager& pcap, const duration datapoint_period, const duration quantum_period )
  : peer_data(datapoint_period, quantum_period),
    pcap_conn(
      pcap.packet_handler(
        std::bind(&Tracker::on_packet, this, arg::_1, arg::_2, arg::_3)
      )
    )
{}

} // namespace Stats