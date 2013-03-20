/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2010 University of Pennsylvania
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "penn-application.h"
#include "ns3/simulator.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

using namespace ns3;


TypeId
PennApplication::GetTypeId ()
{
  static TypeId tid = TypeId ("PennApplication")
    .SetParent<Application> ()
    ;
  return tid;
}

PennApplication::PennApplication ()
{
  m_realStack = false;
}

PennApplication::~PennApplication ()
{
}
  
void
PennApplication::DoDispose ()
{
  Application::DoDispose ();
}

void
PennApplication::SetRealStack (bool realStack)
{
  m_realStack = realStack;
}

bool
PennApplication::IsRealStack ()
{
  return m_realStack;
}

void
PennApplication::SetLocalAddress(Ipv4Address local)
{
  m_local = local;
}

Ipv4Address
PennApplication::GetLocalAddress()
{
  return m_local;
}


void
PennApplication::SetNodeAddressMap (std::map<uint32_t, Ipv4Address> nodeAddressMap)
{
  m_nodeAddressMap = nodeAddressMap;
}

void
PennApplication::SetAddressNodeMap (std::map<Ipv4Address, uint32_t> addressNodeMap)
{
  m_addressNodeMap = addressNodeMap;
}

Ipv4Address
PennApplication::ResolveNodeIpAddress (std::string nodeId)
{
  if (!IsRealStack())
  {  
    uint32_t nodeNumber;
    std::istringstream sin (nodeId);
    sin >> nodeNumber;
    std::map<uint32_t, Ipv4Address>::iterator iter = m_nodeAddressMap.find (nodeNumber);
    if (iter != m_nodeAddressMap.end ())
      { 
        return iter->second;
      }
  }
  // deployment mode
  else
  {
		Ipv4Address remoteIp;
		struct hostent *hp;
		struct in_addr **addr_list;
		hp = gethostbyname(nodeId.c_str());
    if(!hp)
    {
      DEBUG_LOG ("Cannot resolve IP Address for host: " << nodeId);
      return Ipv4Address::GetAny ();
    }
		addr_list = (struct in_addr**)hp->h_addr_list;
	  remoteIp = Ipv4Address (inet_ntoa (*addr_list[0]));
		return remoteIp;
  }
  return Ipv4Address::GetAny ();
}

std::string
PennApplication::ReverseLookup (Ipv4Address ipAddress)
{
  if (!IsRealStack())
  {
    std::map<Ipv4Address, uint32_t>::iterator iter = m_addressNodeMap.find (ipAddress);
    if (iter != m_addressNodeMap.end ())
      { 
        std::ostringstream sin;
        uint32_t nodeNumber = iter->second;
        sin << nodeNumber;    
        return sin.str();
      }
  }
  // deployment mode
  else
  {
    struct sockaddr_in destAddr;
    struct hostent *hp;
    destAddr.sin_family = AF_INET;
    destAddr.sin_addr.s_addr = htonl (ipAddress.Get());
    hp = gethostbyaddr((char*)&destAddr.sin_addr.s_addr,
    sizeof(destAddr.sin_addr.s_addr), AF_INET);
    if (!hp)
    {
      DEBUG_LOG("Could not reverse lookup IP address: " << ipAddress);
      return "Unknown";
    }
    return std::string(hp->h_name);
  }
  return "Unknown";
}
