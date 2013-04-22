#ifndef _GUARD_LIBPCAP_H_
#define _GUARD_LIBPCAP_H_

#ifdef _WIN32
  using u_int = unsigned int;
  using u_short = unsigned short;
  using u_char = unsigned char;
#endif

extern "C" {
  #include <pcap.h>
}

#endif
