/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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

#include "penn-routing-protocol.h"

using namespace ns3;

TypeId
PennRoutingProtocol::GetTypeId (void)
{
  static TypeId tid = TypeId ("PennRoutingProtocol")
    .SetParent<Ipv4RoutingProtocol> ()
    ;
  return tid;
}

PennRoutingProtocol::PennRoutingProtocol ()
{
  g_errorVerbose = true;
}

PennRoutingProtocol::~PennRoutingProtocol ()
{}

void
PennRoutingProtocol::DoDispose ()
{
  Ipv4RoutingProtocol::DoDispose ();
}

