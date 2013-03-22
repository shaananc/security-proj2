#ifndef NEIGHBOUR_H
#define NEIGHBOUR_H

#include "ns3/ipv4-address.h"

using namespace ns3;

struct Neighbour  {
  uint32_t lastHeard;
  Ipv4Address interfaceAddress;
  uint32_t cost;
};

#endif
