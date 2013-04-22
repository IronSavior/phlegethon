#include <iostream>

#include "peer_analysis.h"
#include "stats.h"
#include "config.h"
#include "pcap_manager.h"

#ifdef _WIN32
  #include <boost/thread.hpp>
  #include "b_sleep_for.h"
  namespace this_thread = boost::this_thread;
  using thread = boost::thread;
#else
  #include <thread>
  namespace this_thread = std::this_thread;
  using thread = std::thread;
#endif

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
  
  thread pcap_thread(
    [&pcap]{
      pcap.capture_loop();
    }
  );
  
  Stats::Tracker tracker(pcap, config.sample_period, config.quantum_period);
  std::cout << "Listening..." << std::endl;
  
  size_t dropped_count = 0;
  for(;;) {
    auto _count = pcap.dropped_count();
    if( _count > dropped_count ) {
      std::cerr << "Warning:  " << _count - dropped_count << " packets have been dropped." << std::endl;
      dropped_count = _count;
    }
    
    const Stats::peer_data_t peer_data(tracker.snapshot());
    Analysis::print_status(peer_data, config);
    Analysis::check_events(peer_data, config);
    
    this_thread::sleep_for(config.ui_delay);
  }
  
  pcap_thread.join();
  return 0;
}
