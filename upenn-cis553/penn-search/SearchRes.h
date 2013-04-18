/* 
 * File:   SearchRes.h
 * Author: user
 *
 * Created on March 22, 2013, 3:23 AM
 */

#ifndef SEARCHRES_H
#define	SEARCHRES_H

#include <vector>
#include <string>
#include "ns3/ipv4-address.h"

using namespace ns3;

typedef struct SearchRes {
  Ipv4Address queryNode;
  uint32_t transID;
  std::vector<std::string> keywords;
  std::vector<std::string> docs;
} SearchRes;



#endif	/* SEARCHRES_H */

