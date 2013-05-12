#ifndef _GUARD_PCAP_C_H_
#define _GUARD_PCAP_C_H_
#pragma once

#ifdef _WIN32
  using u_int = unsigned int;
  using u_short = unsigned short;
  using u_char = unsigned char;
#endif

extern "C" {
  #include <pcap.h>
}

#endif
