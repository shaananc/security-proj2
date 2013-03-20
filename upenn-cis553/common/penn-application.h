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

#ifndef PENN_APPLICATION_H
#define PENN_APPLICATION_H

#include "ns3/application.h"
#include "ns3/ptr.h"
#include "ns3/ipv4-address.h"
#include <map>

#include "ns3/penn-log.h"

using namespace ns3; 

class PennApplication : public Application, public PennLog
{
  public:
   static TypeId GetTypeId (void);
   PennApplication ();
   virtual ~PennApplication ();

   // Interface for PennApplication(s)
   virtual void ProcessCommand (std::vector<std::string> tokens) = 0;
   virtual void SetNodeAddressMap (std::map<uint32_t, Ipv4Address> nodeAddressMap);
   virtual void SetAddressNodeMap (std::map<Ipv4Address, uint32_t> addressNodeMap);
   void SetRealStack (bool realStack);
   bool IsRealStack ();
   void SetLocalAddress (Ipv4Address local);
   Ipv4Address GetLocalAddress();
   virtual Ipv4Address ResolveNodeIpAddress (std::string nodeId);
   virtual std::string ReverseLookup (Ipv4Address ipv4Address); 

  protected:
    virtual void DoDispose ();
  private:
    virtual void StartApplication (void) = 0;
    virtual void StopApplication (void) = 0; 
    bool m_realStack;
  protected:
    // Stores local address in the case of Real Stack
    Ipv4Address m_local;
    std::map<uint32_t, Ipv4Address> m_nodeAddressMap;
    std::map<Ipv4Address, uint32_t> m_addressNodeMap;
};    

#endif
