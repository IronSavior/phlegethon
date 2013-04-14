#include <cstdint>
#include <iostream>
#include <sstream>
#include <thread>

#include "stats.h"
#include "config.h"
#include "pcap_manager.h"

std::vector<Stats::peer_spec_t> get_busy_peers( const Stats::peer_data_t& peer_data, const size_t min_bytes ) {
  using std::chrono::seconds;
  std::vector<Stats::peer_spec_t> result;
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

void check_events( const Stats::peer_data_t& peer_data, const Config& config ) {
  using Stats::clock;
  using Net::to_string;
  static auto last_cmd_time = clock::now();
  
  auto busy_peers = get_busy_peers(peer_data, config.min_rate);
  if( !config.event_cmd.empty() && busy_peers.size() > 0 && last_cmd_time < clock::now() - config.cooldown ) {
    last_cmd_time = clock::now();
    for( auto peer = busy_peers.begin(); peer != busy_peers.end(); peer++ ) {
      std::ostringstream cmd;
      cmd << config.event_cmd << " " << Net::to_string(peer->addr);
      std::cout << "Event Script: " << cmd.str() << std::endl;
      system(cmd.str().c_str());
    }
  }
}

void print_status( const Stats::peer_data_t& peer_data, const Config& config ) {
  static bool peer_activity = false;
  auto busy_peers = get_busy_peers(peer_data, config.min_rate);
  if( peer_data.size() > 0 ) {
    peer_activity = true;
    std::cout << "Active Peers: " << busy_peers.size();
    std::cout << " (" << peer_data.size() - busy_peers.size() << " below threshold, not shown)" << std::endl;
    for( auto peer = busy_peers.begin(); peer != busy_peers.end(); peer++ ) {
      std::cout << "   " << Net::to_string(peer->addr) << ":" << peer->port << std::endl;
    }
    std::cout << std::endl;
  }
  else if( peer_activity ) {
    peer_activity = false;
    std::cout << "No peer activity" << std::endl << std::endl;
  }
}

int main( int argc, char **argv ) {
  Config config(argc, argv);
  
  if( config.help ) {
    std::cerr << config.desc() << std::endl;
    return 1;
  }
  
  if( config.host.empty() ) {
    std::cerr << "Error:  Source host is required" << std::endl;
    std::cerr << config.desc() << std::endl;
    return 1;
  }
  
  Pcap::PcapManager pcap(config.interface, config.pcap_filter(), config.cap_timeout);
  if( pcap.has_error() ) {
    std::cerr << "Error while setting up libpcap: ";
    std::cerr << pcap.get_error() << std::endl;
    return 1;
  }
  
  std::thread pcap_thread(
    [&pcap]{
      pcap.capture_loop();
    }
  );
  
  Stats::Tracker tracker(pcap, config.sample_period, config.quantum_period);
  std::cout << "Listening..." << std::endl;
  
  size_t dropped_count = 0;
  for(;;) {
    pcap_stat stats = pcap.stats();
    if( stats.ps_drop > dropped_count ) {
      std::cerr << "Warning:  " << stats.ps_drop - dropped_count << " packets have been dropped." << std::endl;
      dropped_count = stats.ps_drop;
    }
    
    const Stats::peer_data_t peer_data(tracker.snapshot());
    print_status(peer_data, config);
    check_events(peer_data, config);
    
    std::this_thread::sleep_for(config.ui_delay);
  }
  
  pcap_thread.join();
  return 0;
}
