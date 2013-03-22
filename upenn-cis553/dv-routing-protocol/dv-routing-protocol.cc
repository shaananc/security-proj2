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


#include "ns3/dv-routing-protocol.h"
#include "ns3/socket-factory.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/simulator.h"
#include "ns3/log.h"
#include "ns3/random-variable.h"
#include "ns3/inet-socket-address.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv4-route.h"
#include "ns3/uinteger.h"
#include "ns3/test-result.h"
#include <sys/time.h>

#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("DVRoutingProtocol");
NS_OBJECT_ENSURE_REGISTERED (DVRoutingProtocol);

TypeId
DVRoutingProtocol::GetTypeId (void)
{
  static TypeId tid = TypeId ("DVRoutingProtocol")
  .SetParent<PennRoutingProtocol> ()
  .AddConstructor<DVRoutingProtocol> ()
  .AddAttribute ("DVPort",
                 "Listening port for DV packets",
                 UintegerValue (6000),
                 MakeUintegerAccessor (&DVRoutingProtocol::m_dvPort),
                 MakeUintegerChecker<uint16_t> ())
  .AddAttribute ("PingTimeout",
                 "Timeout value for PING_REQ in milliseconds",
                 TimeValue (MilliSeconds (2000)),
                 MakeTimeAccessor (&DVRoutingProtocol::m_pingTimeout),
                 MakeTimeChecker ())
  .AddAttribute ("DiscoveryTimeout",
                 "Time between discovery HELLO_REQ in milliseconds",
                 TimeValue (MilliSeconds (5000)),
                 MakeTimeAccessor (&DVRoutingProtocol::m_discoveryTimeout),
                 MakeTimeChecker ())
  .AddAttribute ("DVTimeout",
                 "Time between UPDATE messages in milliseconds",
                 TimeValue (MilliSeconds (5000)),
                 MakeTimeAccessor (&DVRoutingProtocol::m_dvTimeout),
                 MakeTimeChecker ())
  .AddAttribute ("MaxTTL",
                 "Maximum TTL value for DV packets",
                 UintegerValue (16),
                 MakeUintegerAccessor (&DVRoutingProtocol::m_maxTTL),
                 MakeUintegerChecker<uint8_t> ())
  ;
  return tid;
}

DVRoutingProtocol::DVRoutingProtocol ()
  : m_auditPingsTimer (Timer::CANCEL_ON_DESTROY), m_discoveryTimer (Timer::CANCEL_ON_DESTROY)
{
  RandomVariable random;
  SeedManager::SetSeed (time (NULL));
  random = UniformVariable (0x00000000, 0xFFFFFFFF);
  m_currentSequenceNumber = random.GetInteger ();
  // Setup static routing 
  m_staticRouting = Create<Ipv4StaticRouting> ();
}

DVRoutingProtocol::~DVRoutingProtocol ()
{
}

void 
DVRoutingProtocol::DoDispose ()
{
  // Close sockets
  for (std::map< Ptr<Socket>, Ipv4InterfaceAddress >::iterator iter = m_socketAddresses.begin ();
       iter != m_socketAddresses.end (); iter++)
    {
      iter->first->Close ();
    }
  m_socketAddresses.clear ();
  
  // Clear static routing
  m_staticRouting = 0;

  // Cancel timers
  m_auditPingsTimer.Cancel ();
  m_discoveryTimer.Cancel ();
  m_dvTimer.Cancel ();

  m_pingTracker.clear (); 

  PennRoutingProtocol::DoDispose ();
}

void
DVRoutingProtocol::SetMainInterface (uint32_t mainInterface)
{
  m_mainAddress = m_ipv4->GetAddress (mainInterface, 0).GetLocal ();
}

void
DVRoutingProtocol::SetNodeAddressMap (std::map<uint32_t, Ipv4Address> nodeAddressMap)
{
  m_nodeAddressMap = nodeAddressMap;
}

void
DVRoutingProtocol::SetAddressNodeMap (std::map<Ipv4Address, uint32_t> addressNodeMap)
{
  m_addressNodeMap = addressNodeMap;
}

Ipv4Address
DVRoutingProtocol::ResolveNodeIpAddress (uint32_t nodeNumber)
{
  std::map<uint32_t, Ipv4Address>::iterator iter = m_nodeAddressMap.find (nodeNumber);
  if (iter != m_nodeAddressMap.end ())
    { 
      return iter->second;
    }
  return Ipv4Address::GetAny ();
}

std::string
DVRoutingProtocol::ReverseLookup (Ipv4Address ipAddress)
{
  std::map<Ipv4Address, uint32_t>::iterator iter = m_addressNodeMap.find (ipAddress);
  if (iter != m_addressNodeMap.end ())
    { 
      std::ostringstream sin;
      uint32_t nodeNumber = iter->second;
      sin << nodeNumber;    
      return sin.str();
    }
  return "Unknown";
}

void
DVRoutingProtocol::DoStart ()
{
  // Create sockets
  for (uint32_t i = 0 ; i < m_ipv4->GetNInterfaces () ; i++)
    {
      Ipv4Address ipAddress = m_ipv4->GetAddress (i, 0).GetLocal ();
      if (ipAddress == Ipv4Address::GetLoopback ())
        continue;
      // Create socket on this interface
      Ptr<Socket> socket = Socket::CreateSocket (GetObject<Node> (),
          UdpSocketFactory::GetTypeId ());
      socket->SetAllowBroadcast (true);
      InetSocketAddress inetAddr (m_ipv4->GetAddress (i, 0).GetLocal (), m_dvPort);
      socket->SetRecvCallback (MakeCallback (&DVRoutingProtocol::RecvDVMessage, this));
      if (socket->Bind (inetAddr))
        {
          NS_FATAL_ERROR ("DVRoutingProtocol::DoStart::Failed to bind socket!");
        }
      Ptr<NetDevice> netDevice = m_ipv4->GetNetDevice (i);
      socket->BindToNetDevice (netDevice);
      m_socketAddresses[socket] = m_ipv4->GetAddress (i, 0);
    }
  // Configure timers
  m_auditPingsTimer.SetFunction (&DVRoutingProtocol::AuditPings, this);
  m_discoveryTimer.SetFunction (&DVRoutingProtocol::FloodHello, this);
  m_dvTimer.SetFunction (&DVRoutingProtocol::FloodUpdate, this);

  // Start timers
  m_auditPingsTimer.Schedule (m_pingTimeout);
  m_discoveryTimer.Schedule (m_discoveryTimeout);
  m_dvTimer.Schedule (m_discoveryTimeout + MilliSeconds(2000));
}

Ptr<Ipv4Route>
DVRoutingProtocol::RouteOutput (Ptr<Packet> packet, const Ipv4Header &header, Ptr<NetDevice> outInterface, Socket::SocketErrno &sockerr)
{
  Ptr<Ipv4Route> ipv4Route = m_staticRouting->RouteOutput (packet, header, outInterface, sockerr);
  RoutingTableEntry route;
  if (ipv4Route)  {
    TRAFFIC_LOG ("Found route to: " << ipv4Route->GetDestination () << " via next-hop: " << ipv4Route->GetGateway () << " with source: " << ipv4Route->GetSource () << " and output device " << ipv4Route->GetOutputDevice());
    return ipv4Route;
  }
  // Use dv routing
  ipv4Route = Lookup (header.GetDestination ());
  if (ipv4Route) {
    TRAFFIC_LOG ("Found route to: " << ipv4Route->GetDestination () << " via next-hop: " << ipv4Route->GetGateway () << " with source: " << ipv4Route->GetSource () << " and output device " << ipv4Route->GetOutputDevice());
    return ipv4Route;
  }
  else  {
    TRAFFIC_LOG ("No Route to destination: " << header.GetDestination ());
  }
  return ipv4Route;
}

bool 
DVRoutingProtocol::RouteInput  (Ptr<const Packet> packet, 
  const Ipv4Header &header, Ptr<const NetDevice> inputDev,                            
  UnicastForwardCallback ucb, MulticastForwardCallback mcb,             
  LocalDeliverCallback lcb, ErrorCallback ecb)
{
  Ipv4Address destinationAddress = header.GetDestination ();
  Ipv4Address sourceAddress = header.GetSource ();

  // Drop if packet was originated by this node
  if (IsOwnAddress (sourceAddress) == true)
  {
    return true;
  }

  // Check for local delivery
  uint32_t interfaceNum = m_ipv4->GetInterfaceForDevice (inputDev);
  if (m_ipv4->IsDestinationAddress (destinationAddress, interfaceNum))
  {
    if (!lcb.IsNull ())
    {
      lcb (packet, header, interfaceNum);
      return true;
    }
    else
    {
      return false;
    }
  }

  // Check static routing table
  if (m_staticRouting->RouteInput (packet, header, inputDev, ucb, mcb, lcb, ecb))
  {
    TRAFFIC_LOG ("Found next hop using static routing to destination: " << header.GetDestination ());
    return true;
  }
  // Check dv routing table
  Ptr<Ipv4Route> ipv4Route = Lookup (header.GetDestination ());
  if (ipv4Route) {
    TRAFFIC_LOG ("Found route to: " << ipv4Route->GetDestination () << " via next-hop: " << ipv4Route->GetGateway () << " with source: " << ipv4Route->GetSource () << " and output device " << ipv4Route->GetOutputDevice());
    ucb (ipv4Route, packet, header);  // unicast forwarding callback
    return true;
  }

  TRAFFIC_LOG ("Cannot forward packet. No Route to destination: " << header.GetDestination ());
  return false;
}

Ptr<Ipv4Route>
DVRoutingProtocol::Lookup (Ipv4Address destAddress)
{
  std::map<Ipv4Address, struct RoutingTableEntry>::iterator it = m_routeList.find(destAddress);
  Ptr<Ipv4Route> ipv4Route = 0;
  if (it != m_routeList.end() && it->second.cost < m_maxTTL) {
    ipv4Route = Create<Ipv4Route> ();
    RoutingTableEntry route = it->second;
    ipv4Route->SetDestination (destAddress);
    ipv4Route->SetSource (m_mainAddress);
    ipv4Route->SetGateway (route.nextHopAddr);
    uint32_t interface = m_ipv4->GetInterfaceForAddress(m_neighbourList[route.nextHopAddr].interfaceAddress);
    ipv4Route->SetOutputDevice (m_ipv4->GetNetDevice (interface));
  }

  return ipv4Route;
}

void
DVRoutingProtocol::BroadcastPacket (Ptr<Packet> packet)
{
  for (std::map<Ptr<Socket> , Ipv4InterfaceAddress>::const_iterator i =
      m_socketAddresses.begin (); i != m_socketAddresses.end (); i++)
    {
      Ipv4Address broadcastAddr = i->second.GetLocal ().GetSubnetDirectedBroadcast (i->second.GetMask ());
      i->first->SendTo (packet, 0, InetSocketAddress (broadcastAddr, m_dvPort));
    }
}

void
DVRoutingProtocol::ProcessCommand (std::vector<std::string> tokens)
{
  std::vector<std::string>::iterator iterator = tokens.begin();
  std::string command = *iterator;
  if (command == "PING")
    {
      if (tokens.size() < 3)
        {
          ERROR_LOG ("Insufficient PING params..."); 
          return;
        }
      iterator++;
      std::istringstream sin (*iterator);
      uint32_t nodeNumber;
      sin >> nodeNumber;
      iterator++;
      std::string pingMessage = *iterator;
      Ipv4Address destAddress = ResolveNodeIpAddress (nodeNumber);
      if (destAddress != Ipv4Address::GetAny ())
        {
          uint32_t sequenceNumber = GetNextSequenceNumber ();
          TRAFFIC_LOG ("Sending PING_REQ to Node: " << nodeNumber << " IP: " << destAddress << " Message: " << pingMessage << " SequenceNumber: " << sequenceNumber);
          Ptr<PingRequest> pingRequest = Create<PingRequest> (sequenceNumber, Simulator::Now(), destAddress, pingMessage);
          // Add to ping-tracker
          m_pingTracker.insert (std::make_pair (sequenceNumber, pingRequest));
          Ptr<Packet> packet = Create<Packet> ();
          DVMessage dvMessage = DVMessage (DVMessage::PING_REQ, sequenceNumber, m_maxTTL, m_mainAddress);
          dvMessage.SetPingReq (destAddress, pingMessage);
          packet->AddHeader (dvMessage);
          BroadcastPacket (packet);
        }
    }
  else if (command == "DUMP")
    {
      if (tokens.size() < 2)
        {
          ERROR_LOG ("Insufficient Parameters!");
          return;
        }
      iterator++;
      std::string table = *iterator;
      if (table == "ROUTES" || table == "ROUTING")
        {
          DumpRoutingTable ();
        }
      else if (table == "NEIGHBORS" || table == "NEIGHBOURS")
        {
          DumpNeighbors ();
        }
    }
}

void
DVRoutingProtocol::DumpNeighbors ()
{
  STATUS_LOG (std::endl << "**************** Neighbor List ********************" << std::endl
              << "NeighborNumber\t\tNeighborAddr\t\tInterfaceAddr\t\tLastHeard");
  for (std::map<Ipv4Address , struct Neighbour>::const_iterator i =
      m_neighbourList.begin (); i != m_neighbourList.end (); i++)  {
    uint32_t neighborNum = m_addressNodeMap[i->first];
    Ipv4Address neighborAddr = i->first;
    Ipv4Address ifAddr = i->second.interfaceAddress;
    uint32_t lastHeard = i->second.lastHeard;
    PRINT_LOG (neighborNum << "\t\t\t" << neighborAddr << "\t\t" << ifAddr << "\t\t" << lastHeard);
  /*NOTE: For purpose of autograding, you should invoke the following function for each
  neighbor table entry. The output format is indicated by parameter name and type.
  */
    checkNeighborTableEntry(neighborNum, neighborAddr, ifAddr);
  }
}

void
DVRoutingProtocol::DumpRoutingTable ()
{
  STATUS_LOG (std::endl << "**************** Route Table ********************" << std::endl
              << "DestNumber\t\tDestAddr\t\tNextHopNumber\t\tNextHopAddr\t\tInterfaceAddr\t\tCost");
  for (std::map<Ipv4Address, struct RoutingTableEntry>::const_iterator i = m_routeList.begin ();
       i != m_routeList.end (); i++) {
    uint32_t cost = i->second.cost;
 //   if (cost < m_maxTTL) {
    Ipv4Address destAddr = i->first;
    uint32_t destNum = m_addressNodeMap[destAddr];
    Ipv4Address nextHopAddr = i->second.nextHopAddr;
    uint32_t nextHopNum = m_addressNodeMap[nextHopAddr];
    Ipv4Address ifAddr = m_neighbourList[nextHopAddr].interfaceAddress;

    PRINT_LOG (destNum << "\t\t\t" << destAddr << "\t\t" << nextHopNum << "\t\t\t" << nextHopAddr << "\t\t" 
             << ifAddr << "\t\t" << cost);
  
  /*NOTE: For purpose of autograding, you should invoke the following function for each
  routing table entry. The output format is indicated by parameter name and type.
  */

    if (cost < m_maxTTL) {
      checkRouteTableEntry(destNum, destAddr, nextHopNum, nextHopAddr, ifAddr, cost);
    }
  }
}

void
DVRoutingProtocol::RecvDVMessage (Ptr<Socket> socket)
{
  Address sourceAddr;
  Ptr<Packet> packet = socket->RecvFrom (sourceAddr);
  InetSocketAddress inetSocketAddr = InetSocketAddress::ConvertFrom (sourceAddr);
  Ipv4Address sourceAddress = inetSocketAddr.GetIpv4 ();
  DVMessage dvMessage;
  packet->RemoveHeader (dvMessage);
  
  Ipv4Address interfaceAddress = m_socketAddresses[socket].GetLocal();

  switch (dvMessage.GetMessageType ())
    {
      case DVMessage::PING_REQ:
        ProcessPingReq (dvMessage);
        break;
      case DVMessage::PING_RSP:
        ProcessPingRsp (dvMessage);
        break;
      case DVMessage::HELLO_REQ:
        ProcessHelloReq (dvMessage, interfaceAddress, sourceAddress, socket);
        break;
      case DVMessage::HELLO_RSP:
        ProcessHelloRsp (dvMessage, interfaceAddress);
        break;
      case DVMessage::UPDATE:
        ProcessUpdate (dvMessage);
        break;
      default:
        ERROR_LOG ("Unknown Message Type!" << dvMessage.GetMessageType ());
        break;
    }
}

void
DVRoutingProtocol::ProcessPingReq (DVMessage dvMessage)
{
  // Check destination address
  if (IsOwnAddress (dvMessage.GetPingReq().destinationAddress))
    {
      // Use reverse lookup for ease of debug
      std::string fromNode = ReverseLookup (dvMessage.GetOriginatorAddress ());
      TRAFFIC_LOG ("Received PING_REQ, From Node: " << fromNode << ", Message: " << dvMessage.GetPingReq().pingMessage);
      // Send Ping Response
      DVMessage dvResp = DVMessage (DVMessage::PING_RSP, dvMessage.GetSequenceNumber(), m_maxTTL, m_mainAddress);
      dvResp.SetPingRsp (dvMessage.GetOriginatorAddress(), dvMessage.GetPingReq().pingMessage);
      Ptr<Packet> packet = Create<Packet> ();
      packet->AddHeader (dvResp);
      BroadcastPacket (packet);
    }
}

void
DVRoutingProtocol::ProcessPingRsp (DVMessage dvMessage)
{
  // Check destination address
  if (IsOwnAddress (dvMessage.GetPingRsp().destinationAddress))
    {
      // Remove from pingTracker
      std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
      iter = m_pingTracker.find (dvMessage.GetSequenceNumber ());
      if (iter != m_pingTracker.end ())
        {
          std::string fromNode = ReverseLookup (dvMessage.GetOriginatorAddress ());
          TRAFFIC_LOG ("Received PING_RSP, From Node: " << fromNode << ", Message: " << dvMessage.GetPingRsp().pingMessage);
          m_pingTracker.erase (iter);
        }
      else
        {
          DEBUG_LOG ("Received invalid PING_RSP!");
        }
    }
}

void
DVRoutingProtocol::ProcessHelloReq (DVMessage dvMessage, Ipv4Address interfaceAddress, Ipv4Address sourceAddress, Ptr<Socket> socket)
{
  // Use reverse lookup for ease of debug
  Ipv4Address fromIp = dvMessage.GetOriginatorAddress ();
  std::string fromNode = ReverseLookup (fromIp);
  DEBUG_LOG ("Received HELLO_REQ, From Node: " << fromNode);
  // Check if new entry
  if (m_neighbourList.find(fromIp) == m_neighbourList.end()) {
    struct Neighbour neighbour;
    neighbour.lastHeard = 0;
    neighbour.interfaceAddress = interfaceAddress;
    m_neighbourList.insert(std::make_pair (fromIp, neighbour));
    // Add entry to neighbour socket map
    m_neighbourSocketMap[fromIp] = socket;
    // Add entry to m_routeList if not existing
    if (m_routeList.find(fromIp) == m_routeList.end())  {
      struct RoutingTableEntry newEntry;
      newEntry.nextHopAddr = fromIp;
      newEntry.cost = 1;
      // newEntry.lastHeard = 0;
      m_routeList.insert(std::make_pair (fromIp, newEntry));
    }
    else {
      m_routeList[fromIp].nextHopAddr = fromIp;
      m_routeList[fromIp].cost = 1;
    }
    //if (m_dvTimer.IsRunning() == false) { // Flood routing table update for new neighbor
      FloodUpdateTrig ();
    //}
  }
  else {
    m_neighbourList[fromIp].lastHeard = 0;
  }
  Ptr<Packet> packet = Create<Packet> ();
  DVMessage dvMessageRsp = DVMessage (DVMessage::HELLO_RSP, 0, 1, m_mainAddress);
  packet->AddHeader (dvMessageRsp);
  //socket->SendTo (packet, 0, InetSocketAddress (sourceAddress, m_lsPort));
}

void
DVRoutingProtocol::ProcessHelloRsp (DVMessage dvMessage, Ipv4Address interfaceAddress)
{
  Ipv4Address fromIp = dvMessage.GetOriginatorAddress ();
  std::string fromNode = ReverseLookup (fromIp);
  DEBUG_LOG ("Received HELLO_RSP, From Node: " << fromNode);
  struct Neighbour neighbour;
  neighbour.lastHeard = 0;
  neighbour.interfaceAddress = interfaceAddress;
  m_neighbourList.insert(std::make_pair (fromIp, neighbour));

}

void
DVRoutingProtocol::ProcessUpdate (DVMessage dvMessage) {
  // Use reverse lookup for ease of debug
  Ipv4Address fromIp = dvMessage.GetOriginatorAddress ();
  std::string fromNode = ReverseLookup (fromIp);
  
  DEBUG_LOG ("Received UPDATE, From Node: " << fromNode);
  
  std::map<Ipv4Address, struct RoutingTableEntry> routingTable;
  routingTable = dvMessage.GetUpdate().routingTable;

  // Whether to do triggered update
  bool trig = false;

  // Check if fromIp not present in m_routeList
  // Check all current routing table entry for the same destNdAddr
  for (std::map<Ipv4Address, struct RoutingTableEntry>::iterator recvEntry = routingTable.begin ();  
       recvEntry != routingTable.end (); recvEntry++) {
    Ipv4Address destAddr = recvEntry->first;   
    if(m_routeList.find(destAddr) != m_routeList.end()) {
        if (m_routeList[destAddr].cost > (recvEntry->second.cost + 1))
          // Updates from neighbors provides a smaller cost to the same destination
        {
          m_routeList[destAddr].nextHopAddr = fromIp;
          m_routeList[destAddr].cost = recvEntry->second.cost + 1;
          //m_routeList[destAddr]->second.lastHeard = 0;
          trig = true;
        }
        else if (m_routeList[destAddr].nextHopAddr == fromIp) // Update existing entry
        {
          // m_routeList[destAddr]->second.lastHeard = 0;
          if (recvEntry->second.cost != m_maxTTL) { // Don't count anymore after 16 to prevent count to infinity loops
            m_routeList[destAddr].cost = recvEntry->second.cost + 1;
          }
          else  {
            m_routeList[destAddr].cost = m_maxTTL;
          }
          trig = true;
        }
      }
      
   // Not found in local routing table, means new destination, add it to local table 
    else {
      if (destAddr != m_mainAddress && recvEntry->second.cost < m_maxTTL)
      {
        struct RoutingTableEntry newEntry;
        newEntry.nextHopAddr = fromIp;
        newEntry.cost = recvEntry->second.cost + 1;
        //        newEntry.lastHeard = 0;
        m_routeList.insert(std::make_pair (destAddr, newEntry));
        trig = true;
      }
    } 
  }
 //update routes
 //if (trig == true && m_dvTimer.IsRunning() == false) {
 //if (trig == true) {
    //FloodUpdateTrig ();
  //}
  //}
}

void
DVRoutingProtocol::FloodUpdate () 
{
  for (std::map<Ipv4Address , struct Neighbour>::const_iterator i =
      m_neighbourList.begin (); i != m_neighbourList.end (); i++)  {
    Ipv4Address neighbourAddr = i->first;
    Ptr<Packet> packet = Create<Packet> ();
    DVMessage dvMessage = DVMessage (DVMessage::UPDATE, 0, 1, m_mainAddress);
    std::map<Ipv4Address, struct RoutingTableEntry> routingTable;
    // Customize the routing table
    routingTable = m_routeList;
    
    for (std::map<Ipv4Address, struct RoutingTableEntry>::iterator j =
           routingTable.begin (); j != routingTable.end (); j++)  {
      if (j->second.nextHopAddr == neighbourAddr)
        {
          j->second.cost = m_maxTTL;
        }
    }
    
    dvMessage.SetUpdate (routingTable);
    packet->AddHeader (dvMessage);

    // Broadcast on neighbour facing interface
    Ptr<Socket> socket = m_neighbourSocketMap[neighbourAddr];
    Ipv4InterfaceAddress interfaceAddr = m_socketAddresses[socket];
    Ipv4Address broadcastAddr = interfaceAddr.GetLocal ().GetSubnetDirectedBroadcast (interfaceAddr.GetMask ());
    socket->SendTo (packet, 0, InetSocketAddress (broadcastAddr, m_dvPort));
  }

  m_dvTimer.Schedule (m_dvTimeout);
}

void
DVRoutingProtocol::FloodUpdateTrig () 
{
  for (std::map<Ipv4Address , struct Neighbour>::const_iterator i =
      m_neighbourList.begin (); i != m_neighbourList.end (); i++)  {
    Ipv4Address neighbourAddr = i->first;
    Ptr<Packet> packet = Create<Packet> ();
    DVMessage dvMessage = DVMessage (DVMessage::UPDATE, 0, 1, m_mainAddress);
    std::map<Ipv4Address, struct RoutingTableEntry> routingTable;
    // Customize the routing table
    routingTable = m_routeList;
    
    for (std::map<Ipv4Address, struct RoutingTableEntry>::iterator j =
           routingTable.begin (); j != routingTable.end (); j++)  {
      if (j->second.nextHopAddr == neighbourAddr)
        {
          j->second.cost = m_maxTTL;
        }
    }
    
    dvMessage.SetUpdate (routingTable);
    packet->AddHeader (dvMessage);

    // Broadcast on neighbour facing interface
    Ptr<Socket> socket = m_neighbourSocketMap[neighbourAddr];
    Ipv4InterfaceAddress interfaceAddr = m_socketAddresses[socket];
    Ipv4Address broadcastAddr = interfaceAddr.GetLocal ().GetSubnetDirectedBroadcast (interfaceAddr.GetMask ());
    socket->SendTo (packet, 0, InetSocketAddress (broadcastAddr, m_dvPort));
  }
}

bool
DVRoutingProtocol::IsOwnAddress (Ipv4Address originatorAddress)
{
  // Check all interfaces
  for (std::map<Ptr<Socket> , Ipv4InterfaceAddress>::const_iterator i = m_socketAddresses.begin (); i != m_socketAddresses.end (); i++)
    {
      Ipv4InterfaceAddress interfaceAddr = i->second;
      if (originatorAddress == interfaceAddr.GetLocal ())
        {
          return true;
        }
    }
  return false;

}

void
DVRoutingProtocol::AuditPings ()
{
  std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
  for (iter = m_pingTracker.begin () ; iter != m_pingTracker.end();)
    {
      Ptr<PingRequest> pingRequest = iter->second;
      if (pingRequest->GetTimestamp().GetMilliSeconds() + m_pingTimeout.GetMilliSeconds() <= Simulator::Now().GetMilliSeconds())
        {
          DEBUG_LOG ("Ping expired. Message: " << pingRequest->GetPingMessage () << " Timestamp: " << pingRequest->GetTimestamp().GetMilliSeconds () << " CurrentTime: " << Simulator::Now().GetMilliSeconds ());
          // Remove stale entries
          m_pingTracker.erase (iter++);
        }
      else
        {
          ++iter;
        }
    }
  // Rechedule timer
  m_auditPingsTimer.Schedule (m_pingTimeout); 
}

void
DVRoutingProtocol::FloodHello ()
{
  // remove stale neighbors from the table and update routes
  bool rtTrig = false;
  for (std::map<Ipv4Address , struct Neighbour>::iterator i =
      m_neighbourList.begin (); i != m_neighbourList.end (); i++)  {
    Ipv4Address neighbourAddr = i->first;
    i->second.lastHeard++;
    if (i->second.lastHeard >= 3) {
      STATUS_LOG ("Erasing: " << neighbourAddr);
      m_neighbourList.erase(i);
      for (std::map<Ipv4Address, struct RoutingTableEntry>::iterator j =
             m_routeList.begin (); j != m_routeList.end (); j++)  {
        if (j->second.nextHopAddr == neighbourAddr) {
          j->second.cost = m_maxTTL;
          rtTrig = true;
        }
      }
    }
  }
  //if (rtTrig = true && m_dvTimer.IsRunning() == false) {
  if (rtTrig = true) {
    FloodUpdateTrig ();
  }
  //}
  Ptr<Packet> packet = Create<Packet> ();
  DVMessage dvMessage = DVMessage (DVMessage::HELLO_REQ, 0, 1, m_mainAddress);
  packet->AddHeader (dvMessage);
  BroadcastPacket (packet);
  m_discoveryTimer.Schedule (m_discoveryTimeout); 
}


uint32_t
DVRoutingProtocol::GetNextSequenceNumber ()
{
  return m_currentSequenceNumber++;
}

void 
DVRoutingProtocol::NotifyInterfaceUp (uint32_t i)
{
  m_staticRouting->NotifyInterfaceUp (i);
}
void 
DVRoutingProtocol::NotifyInterfaceDown (uint32_t i)
{
  m_staticRouting->NotifyInterfaceDown (i);
}
void 
DVRoutingProtocol::NotifyAddAddress (uint32_t interface, Ipv4InterfaceAddress address)
{
  m_staticRouting->NotifyAddAddress (interface, address);
}
void 
DVRoutingProtocol::NotifyRemoveAddress (uint32_t interface, Ipv4InterfaceAddress address)
{
  m_staticRouting->NotifyRemoveAddress (interface, address);
}

void
DVRoutingProtocol::SetIpv4 (Ptr<Ipv4> ipv4)
{
  m_ipv4 = ipv4;
  m_staticRouting->SetIpv4 (m_ipv4);
}
