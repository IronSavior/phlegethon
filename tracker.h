#include <boost/thread.hpp>

#include "stats.h"
#include "pcap_manager.h"

class pcap_pkthdr;

namespace Stats {
  class Tracker {
    peer_data_t peer_data;
    boost::signals2::scoped_connection pcap_conn;
    boost::mutex mtx;
    void cleanup();
  public:
    void on_packet( uint8_t* user, const pcap_pkthdr* header, const uint8_t* packet );
    peer_data_t snapshot();
    
    Tracker( Pcap::PcapManager& pcap, const duration datapoint_period, const duration quantum_period );
  };
}
