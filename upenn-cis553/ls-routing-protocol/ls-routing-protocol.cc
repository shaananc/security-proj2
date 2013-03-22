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


#include "ns3/ls-routing-protocol.h"
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

NS_LOG_COMPONENT_DEFINE ("LSRoutingProtocol");
NS_OBJECT_ENSURE_REGISTERED (LSRoutingProtocol);

TypeId
LSRoutingProtocol::GetTypeId (void)
{
  static TypeId tid = TypeId ("LSRoutingProtocol")
  .SetParent<PennRoutingProtocol> ()
  .AddConstructor<LSRoutingProtocol> ()
  .AddAttribute ("LSPort",
                 "Listening port for LS packets",
                 UintegerValue (5000),
                 MakeUintegerAccessor (&LSRoutingProtocol::m_lsPort),
                 MakeUintegerChecker<uint16_t> ())
  .AddAttribute ("PingTimeout",
                 "Timeout value for PING_REQ in milliseconds",
                 TimeValue (MilliSeconds (2000)),
                 MakeTimeAccessor (&LSRoutingProtocol::m_pingTimeout),
                 MakeTimeChecker ())
  .AddAttribute ("DiscoveryTimeout",
                 "Time between discovery HELLO_REQ in milliseconds",
                 TimeValue (MilliSeconds (10000)),
                 MakeTimeAccessor (&LSRoutingProtocol::m_discoveryTimeout),
                 MakeTimeChecker ())
  .AddAttribute ("LSTimeout",
                 "Time between LS_ADVERT messages in milliseconds",
                 TimeValue (MilliSeconds (10000)),
                 MakeTimeAccessor (&LSRoutingProtocol::m_lsTimeout),
                 MakeTimeChecker ())
  .AddAttribute ("RouteTimeout",
                 "Time between scheduled routing table updates in milliseconds",
                 TimeValue (MilliSeconds (30000)),
                 MakeTimeAccessor (&LSRoutingProtocol::m_routeTimeout),
                 MakeTimeChecker ())
  .AddAttribute ("MaxTTL",
                 "Maximum TTL value for LS packets",
                 UintegerValue (16),
                 MakeUintegerAccessor (&LSRoutingProtocol::m_maxTTL),
                 MakeUintegerChecker<uint8_t> ())
  ;
  return tid;
}

LSRoutingProtocol::LSRoutingProtocol ()
  : m_auditPingsTimer (Timer::CANCEL_ON_DESTROY)
{
  RandomVariable random;
  SeedManager::SetSeed (time (NULL));
  random = UniformVariable (0x00000000, 0xFFFFFFFF);
  m_currentSequenceNumber = random.GetInteger ();
  // Ensure non-zero Sequence Number for wrap around
  if (m_currentSequenceNumber == 0) {
    m_currentSequenceNumber++;
  }
  // Setup static routing 
  m_staticRouting = Create<Ipv4StaticRouting> ();
}

LSRoutingProtocol::~LSRoutingProtocol ()
{
}

void 
LSRoutingProtocol::DoDispose ()
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
  m_lsTimer.Cancel ();
  m_routeTimer.Cancel ();
 
  m_pingTracker.clear (); 

  PennRoutingProtocol::DoDispose ();
}

void
LSRoutingProtocol::SetMainInterface (uint32_t mainInterface)
{
  m_mainAddress = m_ipv4->GetAddress (mainInterface, 0).GetLocal ();
}

void
LSRoutingProtocol::SetNodeAddressMap (std::map<uint32_t, Ipv4Address> nodeAddressMap)
{
  m_nodeAddressMap = nodeAddressMap;
}

void
LSRoutingProtocol::SetAddressNodeMap (std::map<Ipv4Address, uint32_t> addressNodeMap)
{
  m_addressNodeMap = addressNodeMap;
}

Ipv4Address
LSRoutingProtocol::ResolveNodeIpAddress (uint32_t nodeNumber)
{
  std::map<uint32_t, Ipv4Address>::iterator iter = m_nodeAddressMap.find (nodeNumber);
  if (iter != m_nodeAddressMap.end ())
    { 
      return iter->second;
    }
  return Ipv4Address::GetAny ();
}

std::string
LSRoutingProtocol::ReverseLookup (Ipv4Address ipAddress)
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
LSRoutingProtocol::DoStart ()
{
  // Create sockets
  for (uint32_t i = 0 ; i < m_ipv4->GetNInterfaces () ; i++)
    {
      Ipv4Address ipAddress = m_ipv4->GetAddress (i, 0).GetLocal ();
      m_ifIpToifNumMap[ipAddress] = i;
      if (ipAddress == Ipv4Address::GetLoopback ())
        continue;
      // Create socket on this interface
      Ptr<Socket> socket = Socket::CreateSocket (GetObject<Node> (),
          UdpSocketFactory::GetTypeId ());
      socket->SetAllowBroadcast (true);
      InetSocketAddress inetAddr (m_ipv4->GetAddress (i, 0).GetLocal (), m_lsPort);
      socket->SetRecvCallback (MakeCallback (&LSRoutingProtocol::RecvLSMessage, this));
      if (socket->Bind (inetAddr))
        {
          NS_FATAL_ERROR ("LSRoutingProtocol::DoStart::Failed to bind socket!");
        }
      Ptr<NetDevice> netDevice = m_ipv4->GetNetDevice (i);
      socket->BindToNetDevice (netDevice);
      m_socketAddresses[socket] = m_ipv4->GetAddress (i, 0);
    }
  // Configure timers
  m_auditPingsTimer.SetFunction (&LSRoutingProtocol::AuditPings, this);
  m_discoveryTimer.SetFunction (&LSRoutingProtocol::FloodHello, this);
  m_lsTimer.SetFunction (&LSRoutingProtocol::AdvertLS, this);
  m_routeTimer.SetFunction (&LSRoutingProtocol::CreateRouteList, this);

  // Start timers
  m_auditPingsTimer.Schedule (m_pingTimeout);
  m_discoveryTimer.Schedule (m_discoveryTimeout);
  m_lsTimer.Schedule (m_discoveryTimeout + MilliSeconds(2000));
  m_routeTimer.Schedule (m_routeTimeout);

  // Set starting sequence number to 1 for debug ease (comment out when finished)
  // m_currentSequenceNumber = 1;
}

Ptr<Ipv4Route>
LSRoutingProtocol::RouteOutput (Ptr<Packet> packet, const Ipv4Header &header, Ptr<NetDevice> outInterface, Socket::SocketErrno &sockerr)
{
  Ptr<Ipv4Route> ipv4Route = m_staticRouting->RouteOutput (packet, header, outInterface, sockerr);
  RouteTableEntry route;
  if (ipv4Route) {
    TRAFFIC_LOG ("Found route using static routing to: " << ipv4Route->GetDestination () << " via next-hop: " << ipv4Route->GetGateway () << " with source: " << ipv4Route->GetSource () << " and output device " << ipv4Route->GetOutputDevice());
    return ipv4Route;
  }
  // Use ls routing
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
LSRoutingProtocol::RouteInput  (Ptr<const Packet> packet, 
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
      TRAFFIC_LOG ("Local delivery for destination: " << header.GetDestination ());
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
  // Check ls routing table
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
LSRoutingProtocol::Lookup (Ipv4Address destAddress)
{
  std::map<Ipv4Address, struct RouteTableEntry>::iterator it = m_routeList.find(destAddress);
  Ptr<Ipv4Route> ipv4Route = 0;
  if (it != m_routeList.end()) {
    ipv4Route = Create<Ipv4Route> ();
    RouteTableEntry route = it->second;
    ipv4Route->SetDestination (destAddress);
    ipv4Route->SetSource (m_mainAddress);
    ipv4Route->SetGateway (route.nextHop);
    ipv4Route->SetOutputDevice (m_ipv4->GetNetDevice (route.interface));
  }
  return ipv4Route;
}

bool
LSRoutingProtocol::CompareLS (const std::vector<Ipv4Address> &neighs1, const std::vector<Ipv4Address> &neighs2)
{
  // Check for size difference
  /*
  DEBUG_LOG(std::endl << "CompareLS" << std::endl);
  DEBUG_LOG("neighs1");
  for (std::vector<Ipv4Address>::const_iterator i =
      neighs1.begin (); i != neighs1.end (); i++)  {
    DEBUG_LOG(*i);
  }
  DEBUG_LOG("neighs2");
  for (std::vector<Ipv4Address>::const_iterator i =
      neighs2.begin (); i != neighs2.end (); i++)  {
    DEBUG_LOG(*i);
  }*/

  if (neighs1.size() != neighs2.size()) {
    //STATUS_LOG("Diff detected in size");
    return true;
  }
  else  {
    for (uint32_t i = 0; i < neighs1.size(); i++)  {
      if(neighs1[i] != neighs2[i])  {
        //STATUS_LOG("Diff detected in element");
        return true;
      }
    }
  }
  return false;
}

void
LSRoutingProtocol::BroadcastPacket (Ptr<Packet> packet)
{
  for (std::map<Ptr<Socket> , Ipv4InterfaceAddress>::const_iterator i =
      m_socketAddresses.begin (); i != m_socketAddresses.end (); i++)
    {
      Ipv4Address broadcastAddr = i->second.GetLocal ().GetSubnetDirectedBroadcast (i->second.GetMask ());
      i->first->SendTo (packet, 0, InetSocketAddress (broadcastAddr, m_lsPort));
    }
}

void
LSRoutingProtocol::ForwardPacket (Ptr<Packet> packet, Ipv4Address sourceIfAddr)
{
  for (std::map<Ptr<Socket> , Ipv4InterfaceAddress>::const_iterator i =
      m_socketAddresses.begin (); i != m_socketAddresses.end (); i++)
    {
      if (i->second.GetLocal() != sourceIfAddr) {
        Ipv4Address broadcastAddr = i->second.GetLocal ().GetSubnetDirectedBroadcast (i->second.GetMask ());
        i->first->SendTo (packet, 0, InetSocketAddress (broadcastAddr, m_lsPort));
      }
    }
}


void
LSRoutingProtocol::ProcessCommand (std::vector<std::string> tokens)
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
          LSMessage lsMessage = LSMessage (LSMessage::PING_REQ, sequenceNumber, m_maxTTL, m_mainAddress);
          lsMessage.SetPingReq (destAddress, pingMessage);
          packet->AddHeader (lsMessage);
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
      else if (table == "LSA")
        {
          DumpLSA ();
        }
      else if (table == "LINKS")
        {
          DumpLinks ();
        }
    }
}

void
LSRoutingProtocol::DumpLSA ()
{
  STATUS_LOG (std::endl << "**************** LSA DUMP ********************" << std::endl
              << "NodeNumber\t\tNodeAddress\t\tNeighbourNumber(s)\t\tNeighbor(s)");
  for (std::map<Ipv4Address , struct LSNode>::const_iterator i =
      m_lsNodeList.begin (); i != m_lsNodeList.end (); i++)  {
    std::vector<Ipv4Address> neighbours = i->second.neighbours;
    Ipv4Address node = i->first;
    uint32_t nodeNum = m_addressNodeMap[node];
    for (std::vector<Ipv4Address>::const_iterator neighPtr = 
      neighbours.begin (); neighPtr != neighbours.end (); neighPtr++) {
      uint32_t neighNum = m_addressNodeMap[*neighPtr];
      PRINT_LOG (nodeNum << "\t\t\t" << node << "\t\t" << neighNum << "\t\t\t\t" << *neighPtr);
    }
  }
}

void
LSRoutingProtocol::DumpLinks ()
{
  STATUS_LOG (std::endl << "**************** LINK DUMP ********************" << std::endl
              << "NodeNumber\t\tNodeAddress\t\tNeighbourNumber(s)\t\tNeighbor(s)");
  for (std::map<Ipv4Address , struct LSNode>::const_iterator i =
      m_lsLinks.begin (); i != m_lsLinks.end (); i++)  {
    std::vector<Ipv4Address> neighbours = i->second.neighbours;
    Ipv4Address node = i->first;
    uint32_t nodeNum = m_addressNodeMap[node];
    for (std::vector<Ipv4Address>::const_iterator neighPtr = 
      neighbours.begin (); neighPtr != neighbours.end (); neighPtr++) {
      uint32_t neighNum = m_addressNodeMap[*neighPtr];
      PRINT_LOG (nodeNum << "\t\t\t" << node << "\t\t" << neighNum << "\t\t\t\t" << *neighPtr);
    }
  }
}

void
LSRoutingProtocol::DumpNeighbors ()
{
  STATUS_LOG (std::endl << "**************** Neighbor List ********************" << std::endl
              << "NeighborNumber\t\tNeighborAddr\t\tInterfaceAddr\t\tLastHeard\t\tCost");
  for (std::map<Ipv4Address , struct Neighbour>::const_iterator i =
      m_neighbourList.begin (); i != m_neighbourList.end (); i++)  {
    uint32_t neighborNum = m_addressNodeMap[i->first];
    Ipv4Address neighborAddr = i->first;
    Ipv4Address ifAddr = i->second.interfaceAddress;
    uint32_t lastHeard = i->second.lastHeard;
    uint32_t ifNum = m_ifIpToifNumMap[ifAddr];
    uint16_t cost = m_ipv4->GetMetric(ifNum);
    
    PRINT_LOG (neighborNum << "\t\t\t" << neighborAddr << "\t\t" << ifAddr << "\t\t" << lastHeard << "\t\t\t" << cost);

  /*NOTE: For purpose of autograding, you should invoke the following function for each
  neighbor table entry. The output format is indicated by parameter name and type.
  */
    checkNeighborTableEntry(neighborNum, neighborAddr, ifAddr);
  }
}

void
LSRoutingProtocol::DumpRoutingTable ()
{
  STATUS_LOG (std::endl << "**************** Route Table ********************" << std::endl
              << "DestNumber\t\tDestAddr\t\tNextHopNumber\t\tNextHopAddr\t\tInterfaceAddr\t\tCost");
  for (std::map<Ipv4Address, struct RouteTableEntry>::const_iterator i = m_routeList.begin ();
       i != m_routeList.end (); i++) {
    Ipv4Address destAddr = i->first;
    uint32_t destNum = m_addressNodeMap[destAddr];
    Ipv4Address nextHopAddr = i->second.nextHop;
    uint32_t nextHopNum = m_addressNodeMap[nextHopAddr];
    Ipv4Address ifAddr = m_neighbourList[nextHopAddr].interfaceAddress;
    uint32_t cost = i->second.cost;

    PRINT_LOG (destNum << "\t\t\t" << destAddr << "\t\t" << nextHopNum << "\t\t\t" << nextHopAddr << "\t\t" 
               << ifAddr << "\t\t" << cost);

	/*NOTE: For purpose of autograding, you should invoke the following function for each
	routing table entry. The output format is indicated by parameter name and type.
	*/
    checkRouteTableEntry(destNum, destAddr, nextHopNum, nextHopAddr, ifAddr, cost);
  }
}

void
LSRoutingProtocol::RecvLSMessage (Ptr<Socket> socket)
{
  Address sourceAddr;
  Ptr<Packet> packet = socket->RecvFrom (sourceAddr);
  InetSocketAddress inetSocketAddr = InetSocketAddress::ConvertFrom (sourceAddr);
  Ipv4Address sourceAddress = inetSocketAddr.GetIpv4 ();
  LSMessage lsMessage;
  packet->RemoveHeader (lsMessage);

  Ipv4Address interfaceAddress = m_socketAddresses[socket].GetLocal();

  switch (lsMessage.GetMessageType ())
    {
      case LSMessage::PING_REQ:
        ProcessPingReq (lsMessage);
        break;
      case LSMessage::PING_RSP:
        ProcessPingRsp (lsMessage);
        break;
      case LSMessage::HELLO_REQ:
        ProcessHelloReq (lsMessage, interfaceAddress, sourceAddress, socket);
        break;
      case LSMessage::HELLO_RSP:
        ProcessHelloRsp (lsMessage, interfaceAddress);
        break;
      case LSMessage::LS_ADVERT:
        ProcessLSAdvert (lsMessage, interfaceAddress);
        break;
      default:
        ERROR_LOG ("Unknown Message Type!");
        break;
    }
}

void
LSRoutingProtocol::ProcessPingReq (LSMessage lsMessage)
{
  // Check destination address
  if (IsOwnAddress (lsMessage.GetPingReq().destinationAddress))
    {
      // Use reverse lookup for ease of debug
      std::string fromNode = ReverseLookup (lsMessage.GetOriginatorAddress ());
      TRAFFIC_LOG ("Received PING_REQ, From Node: " << fromNode << ", Message: " << lsMessage.GetPingReq().pingMessage);
      // Send Ping Response
      LSMessage lsResp = LSMessage (LSMessage::PING_RSP, lsMessage.GetSequenceNumber(), m_maxTTL, m_mainAddress);
      lsResp.SetPingRsp (lsMessage.GetOriginatorAddress(), lsMessage.GetPingReq().pingMessage);
      Ptr<Packet> packet = Create<Packet> ();
      packet->AddHeader (lsResp);
      BroadcastPacket (packet);
    }
}

void
LSRoutingProtocol::ProcessPingRsp (LSMessage lsMessage)
{
  // Check destination address
  if (IsOwnAddress (lsMessage.GetPingRsp().destinationAddress))
    {
      // Remove from pingTracker
      std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
      iter = m_pingTracker.find (lsMessage.GetSequenceNumber ());
      if (iter != m_pingTracker.end ())
        {
          std::string fromNode = ReverseLookup (lsMessage.GetOriginatorAddress ());
          TRAFFIC_LOG ("Received PING_RSP, From Node: " << fromNode << ", Message: " << lsMessage.GetPingRsp().pingMessage);
          m_pingTracker.erase (iter);
        }
      else
        {
          DEBUG_LOG ("Received invalid PING_RSP!");
        }
    }
}

void
LSRoutingProtocol::ProcessHelloReq (LSMessage lsMessage, Ipv4Address interfaceAddress, Ipv4Address sourceAddress, Ptr<Socket> socket)
{
  // Use reverse lookup for ease of debug
  Ipv4Address fromIp = lsMessage.GetOriginatorAddress ();
  std::string fromNode = ReverseLookup (fromIp);
  DEBUG_LOG ("Received HELLO_REQ, From Node: " << fromNode);
  // Check if new entry
  if (m_neighbourList.find(fromIp) == m_neighbourList.end()) {
    struct Neighbour neighbour;
    neighbour.lastHeard = 0;
    neighbour.interfaceAddress = interfaceAddress;
    m_neighbourList.insert(std::make_pair (fromIp, neighbour));
    // Triggered Update
    if (m_lsTimer.IsRunning() == false) {
      m_currentSequenceNumber++;
      AdvertLS();
    }
    BootstrapNeighbour(fromIp, socket);
  }
  else {
  m_neighbourList[fromIp].lastHeard = 0;
  }
  Ptr<Packet> packet = Create<Packet> ();
  LSMessage lsMessageRsp = LSMessage (LSMessage::HELLO_RSP, 0, 1, m_mainAddress);
  packet->AddHeader (lsMessageRsp);
  //socket->SendTo (packet, 0, InetSocketAddress (sourceAddress, m_lsPort));
}

void
LSRoutingProtocol::ProcessHelloRsp (LSMessage lsMessage, Ipv4Address interfaceAddress)
{
  Ipv4Address fromIp = lsMessage.GetOriginatorAddress ();
  std::string fromNode = ReverseLookup (fromIp);
  DEBUG_LOG ("Received HELLO_RSP, From Node: " << fromNode);
  // Check if new entry
  if (m_neighbourList.find(fromIp) == m_neighbourList.end()) {
    struct Neighbour neighbour;
    neighbour.lastHeard = 0;
    neighbour.interfaceAddress = interfaceAddress;
    m_neighbourList.insert(std::make_pair (fromIp, neighbour));
    // Triggered Update
    if (m_lsTimer.IsRunning() == false) {
      m_currentSequenceNumber++;
      AdvertLS();
    }
  }
  // Reset lastHeard for existing entry
  else {
    m_neighbourList[fromIp].lastHeard = 0;
  }
}

void
LSRoutingProtocol::ProcessLSAdvert (LSMessage lsMessage, Ipv4Address interfaceAddress)
{
  Ipv4Address fromIp = lsMessage.GetOriginatorAddress ();
  std::string fromNode = ReverseLookup (fromIp);
  uint32_t newSeqNum = lsMessage.GetSequenceNumber ();
  DEBUG_LOG ("Received LS_ADVERT, From Node: " << fromNode << ", Sequence #: " << newSeqNum);
  
  struct LSNode lsNode;
  lsNode.seqNum = newSeqNum;
  lsNode.neighbours = lsMessage.GetLsAd().neighbours;

  // Check if fromIp not present in m_lsNodeList
  if  (m_lsNodeList.count(fromIp) == 0) {
    m_lsNodeList[fromIp] = lsNode;
    // Compute new Routes
    //STATUS_LOG("Computing routes on new LSA");
    if (m_routeTimer.IsRunning() == false) {
      //STATUS_LOG("CreateRouteList on new LSA");
      CreateRouteList ();
    }
  }
  /* update information to reflect new LSA if more recent sequence number and any change in LSA*/
  else if (newSeqNum > m_lsNodeList[fromIp].seqNum || (newSeqNum == 0 && m_lsNodeList[fromIp].seqNum != 0)) {
    if (CompareLS(lsNode.neighbours, m_lsNodeList[fromIp].neighbours)) {
      // Compute new Routes
      DEBUG_LOG("Computing routes on updated LSA");
      m_lsNodeList[fromIp] = lsNode;
      //if (m_routeTimer.IsRunning() == false) {
        CreateRouteListTrig ();
      //}
    }
    else  {
      m_lsNodeList[fromIp] = lsNode;
    }
  }
  // else drop the packet
  else  { 
    return;
  }
  // rebroadcast the LS message from this node to all neighbors except original sender
  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (lsMessage);
  ForwardPacket (packet, interfaceAddress);
}

void
LSRoutingProtocol::CreateRouteList ()
{
  // Compute links
  for (std::map<Ipv4Address , struct LSNode>::const_iterator i =
      m_lsNodeList.begin (); i != m_lsNodeList.end (); i++)  {
    Ipv4Address nodeIp = i->first;
    struct LSNode lsNode;
    for (std::vector<Ipv4Address>::const_iterator neighIpPtr = 
      i->second.neighbours.begin (); neighIpPtr != i->second.neighbours.end (); neighIpPtr++)  {
      std::vector<Ipv4Address> neighbours = m_lsNodeList[*neighIpPtr].neighbours;
      if (std::find(neighbours.begin(), neighbours.end(), nodeIp) != neighbours.end()) {
        lsNode.neighbours.push_back(*neighIpPtr);
      }
    }
    m_lsLinks[nodeIp] = lsNode;
  }

  struct RouteTableEntry cNH;
  std::map<Ipv4Address, struct RouteTableEntry> m_knownList;
  std::map<Ipv4Address, struct RouteTableEntry> m_unknownList;
  cNH.cost = 1;
  for (std::map<Ipv4Address , struct Neighbour>::const_iterator i =
      m_neighbourList.begin (); i != m_neighbourList.end (); i++)  {
    cNH.nextHop = i->first;
    cNH.interface = m_ipv4->GetInterfaceForAddress(m_neighbourList[cNH.nextHop].interfaceAddress);
    m_unknownList.insert(std::make_pair (i->first, cNH));
  }
  while (!m_unknownList.empty()) {
    Ipv4Address moveNode = m_unknownList.begin()->first;
    for (std::map<Ipv4Address , struct RouteTableEntry>::const_iterator i =
           m_unknownList.begin (); i != m_unknownList.end (); i++)  {
      if (i->second.cost < m_unknownList[moveNode].cost) {
        moveNode = i->first;
      }
    }
    m_knownList.insert(std::make_pair (moveNode, m_unknownList[moveNode]));
    std::map<Ipv4Address, struct RouteTableEntry>::iterator delNode = m_unknownList.find(moveNode);
    m_unknownList.erase(delNode);
    cNH.cost = m_knownList[moveNode].cost + 1;
    cNH.nextHop = m_knownList[moveNode].nextHop;
    cNH.interface = m_ipv4->GetInterfaceForAddress(m_neighbourList[cNH.nextHop].interfaceAddress);
    std::vector<Ipv4Address> nNodes = m_lsLinks[moveNode].neighbours;
    std::vector<Ipv4Address>::size_type nNodesSize = nNodes.size();
    for (uint16_t i = 0; i < nNodesSize; i++)  {
      Ipv4Address addNode = nNodes[i];
      if  (m_knownList.count(addNode) == 0 && m_unknownList.count(addNode) == 0 && addNode != m_mainAddress) {
        m_unknownList.insert (std::make_pair (addNode, cNH));
      }
    }
  }
  m_routeList = m_knownList;
  m_routeTimer.Schedule (m_routeTimeout);
}

void
LSRoutingProtocol::CreateRouteListTrig ()
{
  // Compute links
  for (std::map<Ipv4Address , struct LSNode>::const_iterator i =
      m_lsNodeList.begin (); i != m_lsNodeList.end (); i++)  {
    Ipv4Address nodeIp = i->first;
    struct LSNode lsNode;
    for (std::vector<Ipv4Address>::const_iterator neighIpPtr = 
      i->second.neighbours.begin (); neighIpPtr != i->second.neighbours.end (); neighIpPtr++)  {
      std::vector<Ipv4Address> neighbours = m_lsNodeList[*neighIpPtr].neighbours;
      if (std::find(neighbours.begin(), neighbours.end(), nodeIp) != neighbours.end()) {
        lsNode.neighbours.push_back(*neighIpPtr);
      }
    }
    m_lsLinks[nodeIp] = lsNode;
  }

  struct RouteTableEntry cNH;
  std::map<Ipv4Address, struct RouteTableEntry> m_knownList;
  std::map<Ipv4Address, struct RouteTableEntry> m_unknownList;
  cNH.cost = 1;
  for (std::map<Ipv4Address , struct Neighbour>::const_iterator i =
      m_neighbourList.begin (); i != m_neighbourList.end (); i++)  {
    cNH.nextHop = i->first;
    cNH.interface = m_ipv4->GetInterfaceForAddress(m_neighbourList[cNH.nextHop].interfaceAddress);
    m_unknownList.insert(std::make_pair (i->first, cNH));
  }
  while (!m_unknownList.empty()) {
    Ipv4Address moveNode = m_unknownList.begin()->first;
    for (std::map<Ipv4Address , struct RouteTableEntry>::const_iterator i =
           m_unknownList.begin (); i != m_unknownList.end (); i++)  {
      if (i->second.cost < m_unknownList[moveNode].cost) {
        moveNode = i->first;
      }
    }
    m_knownList.insert(std::make_pair (moveNode, m_unknownList[moveNode]));
    std::map<Ipv4Address, struct RouteTableEntry>::iterator delNode = m_unknownList.find(moveNode);
    m_unknownList.erase(delNode);
    cNH.cost = m_knownList[moveNode].cost + 1;
    cNH.nextHop = m_knownList[moveNode].nextHop;
    cNH.interface = m_ipv4->GetInterfaceForAddress(m_neighbourList[cNH.nextHop].interfaceAddress);
    std::vector<Ipv4Address> nNodes = m_lsLinks[moveNode].neighbours;
    std::vector<Ipv4Address>::size_type nNodesSize = nNodes.size();
    for (uint16_t i = 0; i < nNodesSize; i++)  {
      Ipv4Address addNode = nNodes[i];
      if  (m_knownList.count(addNode) == 0 && m_unknownList.count(addNode) == 0 && addNode != m_mainAddress) {
        m_unknownList.insert (std::make_pair (addNode, cNH));
      }
    }
  }
  m_routeList = m_knownList;
}


bool
LSRoutingProtocol::IsOwnAddress (Ipv4Address originatorAddress)
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
LSRoutingProtocol::AuditPings ()
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
LSRoutingProtocol::FloodHello ()
{
  // remove stale neighbors from the table
  for (std::map<Ipv4Address , struct Neighbour>::iterator i =
      m_neighbourList.begin (); i != m_neighbourList.end (); i++)  {
    Ipv4Address neighbourAddr = i->first;
    i->second.lastHeard++;
    if (i->second.lastHeard >= 3) {
      STATUS_LOG ("Erasing: " << neighbourAddr);
      m_neighbourList.erase(i);
      // Triggered Update
      if (m_lsTimer.IsRunning() == false) {
        m_currentSequenceNumber++;
        AdvertLS();
      }
    }
  }
  Ptr<Packet> packet = Create<Packet> ();
  LSMessage lsMessage = LSMessage (LSMessage::HELLO_REQ, 0, 1, m_mainAddress);
  packet->AddHeader (lsMessage);
  BroadcastPacket (packet);
  m_discoveryTimer.Schedule (m_discoveryTimeout); 
}

void
LSRoutingProtocol::AdvertLS ()
{
  Ptr<Packet> packet = Create<Packet> ();
  LSMessage lsMessage = LSMessage (LSMessage::LS_ADVERT, m_currentSequenceNumber, 1, m_mainAddress);
  std::vector<Ipv4Address> neighbours;
  for (std::map<Ipv4Address , struct Neighbour>::const_iterator i =
      m_neighbourList.begin (); i != m_neighbourList.end (); i++)  {
    Ipv4Address neighbourAddr = i->first;
    neighbours.push_back(neighbourAddr);
  }

  // store self neighbours in m_lsNodeList
  struct LSNode lsNode;
  lsNode.seqNum = m_currentSequenceNumber;
  lsNode.neighbours = neighbours;
  m_lsNodeList[m_mainAddress] = lsNode;

  lsMessage.SetLsAd (neighbours);
  packet->AddHeader (lsMessage);
  BroadcastPacket (packet);
  m_lsTimer.Schedule (m_lsTimeout); 
  m_currentSequenceNumber++;
}

void
LSRoutingProtocol::AdvertLSTrig ()
{
  Ptr<Packet> packet = Create<Packet> ();
  LSMessage lsMessage = LSMessage (LSMessage::LS_ADVERT, m_currentSequenceNumber, 1, m_mainAddress);
  std::vector<Ipv4Address> neighbours;
  for (std::map<Ipv4Address , struct Neighbour>::const_iterator i =
      m_neighbourList.begin (); i != m_neighbourList.end (); i++)  {
    Ipv4Address neighbourAddr = i->first;
    neighbours.push_back(neighbourAddr);
  }

  // store self neighbours in m_lsNodeList
  struct LSNode lsNode;
  lsNode.seqNum = m_currentSequenceNumber;
  lsNode.neighbours = neighbours;
  m_lsNodeList[m_mainAddress] = lsNode;

  lsMessage.SetLsAd (neighbours);
  packet->AddHeader (lsMessage);
  BroadcastPacket (packet);
  m_currentSequenceNumber++;
}

void
LSRoutingProtocol::BootstrapNeighbour (Ipv4Address neighAddress, Ptr<Socket> socket)
{
  //STATUS_LOG("Bootstrap: " << m_addressNodeMap[neighAddress]);
  for (std::map<Ipv4Address , struct LSNode>::const_iterator i =
      m_lsNodeList.begin (); i != m_lsNodeList.end (); i++)  {
    std::vector<Ipv4Address> neighbours = i->second.neighbours;
    uint32_t seqNum = i->second.seqNum;
    Ipv4Address originator = i->first;
    Ptr<Packet> packet = Create<Packet> ();
    LSMessage lsMessage = LSMessage (LSMessage::LS_ADVERT, seqNum, 1, originator);
    lsMessage.SetLsAd (neighbours);
    packet->AddHeader (lsMessage);
    //socket->SendTo (packet, 0, InetSocketAddress (neighAddress, m_lsPort));

    // Broadcast on neighbour facing interface
    Ipv4InterfaceAddress interfaceAddr = m_socketAddresses[socket];
    Ipv4Address broadcastAddr = interfaceAddr.GetLocal ().GetSubnetDirectedBroadcast (interfaceAddr.GetMask ());
    socket->SendTo (packet, 0, InetSocketAddress (broadcastAddr, m_lsPort));
  }
 
}

uint32_t
LSRoutingProtocol::GetNextSequenceNumber ()
{
  return m_currentSequenceNumber++;
}

void 
LSRoutingProtocol::NotifyInterfaceUp (uint32_t i)
{
  m_staticRouting->NotifyInterfaceUp (i);
}
void 
LSRoutingProtocol::NotifyInterfaceDown (uint32_t i)
{
  m_staticRouting->NotifyInterfaceDown (i);
}
void 
LSRoutingProtocol::NotifyAddAddress (uint32_t interface, Ipv4InterfaceAddress address)
{
  m_staticRouting->NotifyAddAddress (interface, address);
}
void 
LSRoutingProtocol::NotifyRemoveAddress (uint32_t interface, Ipv4InterfaceAddress address)
{
  m_staticRouting->NotifyRemoveAddress (interface, address);
}

void
LSRoutingProtocol::SetIpv4 (Ptr<Ipv4> ipv4)
{
  m_ipv4 = ipv4;
  m_staticRouting->SetIpv4 (m_ipv4);
}
