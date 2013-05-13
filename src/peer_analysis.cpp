#include <chrono>
#include <iostream>
#include <sstream>

#include "stats.h"
#include "net.h"
#include "config.h"
#include "peer_analysis.h"

namespace Analysis {

void check_events( const Stats::peer_data_t& peer_data, const Config& config ) {
  using Stats::clock;
  using Net::to_string;
  static auto last_cmd_time = clock::time_point();
  
  auto busy_peers = get_busy_peers(peer_data, config.min_rate);
  if( !config.event_cmd.empty() && busy_peers.size() > 0 && last_cmd_time < clock::now() - config.cooldown ) {
    last_cmd_time = clock::now();
    for( auto peer = busy_peers.begin(); peer != busy_peers.end(); peer++ ) {
      std::ostringstream cmd;
      cmd << config.event_cmd << " " << Net::to_string(peer->addr);
      std::cout << std::endl << "Event Script: " << cmd.str() << std::endl;
      system(cmd.str().c_str());
    }
  }
}

void print_status( const Stats::peer_data_t& peer_data, const Config& config ) {
  static auto print_after = Stats::clock::time_point();
  auto now = Stats::clock::now();
  if( now < print_after ) return;

  static bool peer_activity = false;
  auto busy_peers = get_busy_peers(peer_data, config.min_rate);
  if( peer_data.size() > 0 ) {
    std::cout << std::endl << "Active Peers: " << busy_peers.size();
    std::cout << " (" << peer_data.size() - busy_peers.size() << " below threshold, not shown)";
    for( auto peer = busy_peers.begin(); peer != busy_peers.end(); peer++ ) {
      std::cout << std::endl << "   " << Net::to_string(peer->addr) << ":" << peer->port;
    }
    std::cout << std::endl;
    print_after = now + config.ui_delay;
    peer_activity = true;
  }
  else if( peer_activity ) {
    peer_activity = false;
    std::cout << std::endl << "No peer activity" << std::endl;
  }
}

peer_list_t get_busy_peers( const Stats::peer_data_t& peer_data, const size_t min_bytes ) {
  using std::chrono::seconds;
  peer_list_t result;
  for( auto peer = peer_data.begin(); peer != peer_data.end(); peer++ ) {
    const Stats::data_point_t& dp = peer->second;
    unsigned long count = 0;
    for( auto sample = dp.begin(); sample != dp.end(); sample++ ) {
      count += sample->bytes;
    }
    if( count > min_bytes * (peer_data.datapoint_period / seconds(1)) ) {
      auto peer_spec = Stats::peer_spec_t(peer->first.addr, peer->first.port);
      result.push_back(peer_spec);
    }
  }
  return result;
}

} // namespace Analysis
