#include <chrono>
#include <string>
#include <sstream>
#include <boost/program_options.hpp>

#include "config.h"
#include "stats.h"

namespace opt = boost::program_options;

const opt::options_description Config::desc() {
  return _desc;
}

std::string Config::pcap_filter() {
  if( !filter.empty() ) return filter;
  std::ostringstream s;
  s << "udp and not net 65.52.0.0/14";
  s << " and src host " << host;
  s << " and src port " << port;
  return s.str();
}

Config::Config( const int argc, const char* const argv[] ) : _desc("Options") {
  using std::chrono::seconds;
  using std::chrono::milliseconds;
  _desc.add_options()
    ("help",
      opt::bool_switch(&help),
      "display help")
    
    ("list-interfaces,L",
      opt::bool_switch(&list_interfaces),
      "Show a list of network interfaces")
    
    ("interface,i",
      opt::value<std::string>(&interface)->default_value(std::string()),
      "Capture interface")

    ("cap-timeout",
      opt::value<unsigned long>(&cap_timeout)->default_value(100),
      "Capture timeout in milliseconds")
    
    ("host,h",
      opt::value<std::string>(&host)->default_value(std::string()),
      "Source address (ignored when used with --filter)")
    
    ("port,p",
      opt::value<unsigned long>(&port)->default_value(3074),
      "UDP source port (ignored when used with --filter)")
    
    ("filter,f",
      opt::value<std::string>(&filter)->default_value(std::string()),
      "Override default pcap fitler")
    
    ("min-rate",
      opt::value<size_t>(&min_rate)->default_value(2200),
      "Minimum rate in bytes-per-second")
    
    ("ui-delay",
      opt::value<unsigned long>(&_ui_delay)->default_value(1000),
      "Milliseconds between UI updates")
    
    ("on-event,e",
      opt::value<std::string>(&event_cmd)->default_value(std::string()),
      "Command to execute when event is observed")
    
    ("cooldown",
      opt::value<unsigned long>(&_cooldown)->default_value(15),
      "Minimum time (in seconds) between command executions for the same host")
    
    ("sample-period",
      opt::value<unsigned long>(&_sample_period)->default_value(30000),
      "Number of milliseconds over which to measure samples (Must be a multiple of quantum-period)")
    
    ("quantum",
      opt::value<unsigned long>(&_quantum_period)->default_value(200),
      "Number of milliseconds representing the smallest discrete interval that can be measured")
  ;
  opt::store(opt::parse_command_line(argc, argv, _desc), _vars);
  opt::notify(_vars);
  
  ui_delay = milliseconds(_ui_delay);
  cooldown = seconds(_cooldown);
  sample_period = milliseconds(_sample_period);
  quantum_period = milliseconds(_quantum_period);
}
