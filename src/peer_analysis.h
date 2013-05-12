#ifndef _GUARD_PEER_ANALYSIS_H_
#define _GUARD_PEER_ANALYSIS_H_
#pragma once

#include <vector>

class Config;
namespace Stats {
  class peer_data_t;
  class peer_spec_t;
}

namespace Analysis {
  using peer_list_t = std::vector<Stats::peer_spec_t>;
  
  void check_events( const Stats::peer_data_t& peer_data, const Config& config );
  void print_status( const Stats::peer_data_t& peer_data, const Config& config );
  peer_list_t get_busy_peers( const Stats::peer_data_t& peer_data, const size_t min_bytes );
}

#endif
