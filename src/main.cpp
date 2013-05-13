#include <iostream>

#include "peer_analysis.h"
#include "tracker.h"
#include "config.h"
#include "libpcap.h"

#ifdef _WIN32
  #include <boost/thread.hpp>
  #include "b_sleep_for.h"
  namespace this_thread = boost::this_thread;
  using thread_t = boost::thread;
#else
  #include <thread>
  namespace this_thread = std::this_thread;
  using thread_t = std::thread;
#endif

void print_interfaces( std::ostream& stream ) {
  stream << "Available interfaces:" << std::endl;
  auto list = libpcap::interfaces();
  for( auto iface = list.begin(); iface != list.end(); ++iface ) {
    stream << "  " << iface->name;
    if( !iface->description.empty() ) stream << "  [" << iface->description << "]";
    stream << std::endl;
  }
}

int main( int argc, char **argv ) {
  Config config(argc, argv);
  
  if( config.help ) {
    std::cout << config.desc() << std::endl;
    return 0;
  }
  
  if( config.list_interfaces ) {
    print_interfaces(std::cout);
    return 0;
  }
  
  if( config.host.empty() && config.filter.empty() ) {
    std::cerr << "Error:  One of either --host or --filter is required." << std::endl;
    std::cerr << config.desc() << std::endl;
    return 1;
  }
  
  if( config.interface.empty() ) {
    std::cerr << "Error:  You must specify the network interface. (-i)" << std::endl;
    std::cerr << config.desc() << std::endl;
    print_interfaces(std::cerr);
    return 1;
  }
  
  libpcap::live_capture pcap(config.interface, config.pcap_filter(), config.cap_timeout);
  if( pcap.has_error() ) {
    std::cerr << "Error while setting up libpcap: ";
    std::cerr << pcap.get_error() << std::endl;
    return 1;
  }
  
  thread_t pcap_thread(
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
    
    const auto peer_data = tracker.snapshot();
    Analysis::print_status(peer_data, config);
    Analysis::check_events(peer_data, config);
    
    this_thread::sleep_for(config.quantum_period);
  }
  
  pcap_thread.join();
  return 0;
}
