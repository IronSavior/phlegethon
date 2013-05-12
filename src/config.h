#ifndef _GUARD_CONFIG_H_
#define _GUARD_CONFIG_H_
#pragma once

#include <chrono>
#include <string>
#include <boost/program_options.hpp>

#include "net.h"

class Config {
  using clock = std::chrono::system_clock;
  boost::program_options::options_description _desc;
  boost::program_options::variables_map       _vars;
  int _cooldown;
  int _ui_delay;
  int _sample_period;
  int _quantum_period;

public:
  bool            help;
  bool            list_interfaces;
  std::string     interface;
  std::string     host;
  std::string     filter;
  std::string     event_cmd;
  size_t          min_rate;
  int             port;
  int             cap_timeout;
  clock::duration cooldown;
  clock::duration ui_delay;
  clock::duration sample_period;
  clock::duration quantum_period;
  
  const boost::program_options::options_description desc();
  
  std::string pcap_filter();

  Config() = delete;
  Config( const int argc, const char* const argv[] );
};
#endif
