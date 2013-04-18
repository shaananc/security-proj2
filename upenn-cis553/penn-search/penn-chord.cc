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



/* Hash printing code adapted from http://ubuntuforums.org/showthread.php?t=1612675 */

// TODO Keep-Alive Messages
// TODO Clear up params
// TODO Change remote_node usage
// TODO Change logic to callbacks, register them

#include "penn-chord.h"

#include "ns3/random-variable.h"
#include "ns3/inet-socket-address.h"
#include "NodeInfo.h"
#include "remote_node.h"

#include <openssl/sha.h>

using namespace ns3;

uint32_t num_hops = 0;
uint32_t num_lookups = 0;
bool inLookup = false;

class remote_node;

TypeId
PennChord::GetTypeId() {
    static TypeId tid = TypeId("PennChord")
            .SetParent<PennApplication> ()
            .AddConstructor<PennChord> ()
            .AddAttribute("AppPort",
            "Listening port for Application",
            UintegerValue(19481),
            MakeUintegerAccessor(&PennChord::m_appPort),
            MakeUintegerChecker<uint16_t> ())
            .AddAttribute("PingTimeout",
            "Timeout value for PING_REQ in milliseconds",
            TimeValue(MilliSeconds(2000)),
            MakeTimeAccessor(&PennChord::m_pingTimeout),
            MakeTimeChecker())

            .AddAttribute("StabilizeFreq",
            "Frequency to Update Successor",
            TimeValue(MilliSeconds(1500)),
            MakeTimeAccessor(&PennChord::m_stabilizeFreq),
            MakeTimeChecker())

            .AddAttribute("RequestTimeout",
            "Timeout value for request retransmission in milli seconds",
            TimeValue(MilliSeconds(2000)),
            MakeTimeAccessor(&PennChord::m_requestTimeout),
            MakeTimeChecker())

            .AddAttribute("RingDebugTimeout",
            "Timeout value for debug request retransmission in milli seconds",
            TimeValue(MilliSeconds(20000)),
            MakeTimeAccessor(&PennChord::m_debugTimeout),
            MakeTimeChecker())

            .AddAttribute("FixFingerInterval",
            "Fix finger interval in milli seconds",
            TimeValue(MilliSeconds(25000)),
            MakeTimeAccessor(&PennChord::m_fixFingerInterval),
            MakeTimeChecker())

            .AddAttribute("AuditFingerInterval",
            "Audit finger intitial interval in milli seconds",
            TimeValue(MilliSeconds(19000)),
            MakeTimeAccessor(&PennChord::m_auditFingerInterval),
            MakeTimeChecker())

            .AddAttribute("MaxRequestRetries",
            "Number of request retries before giving up",
            UintegerValue(3),
            MakeUintegerAccessor(&PennChord::m_maxRequestRetries),
            MakeUintegerChecker<uint8_t> ())
            ;
    return tid;
}

PennChord::PennChord()
: m_auditPingsTimer(Timer::CANCEL_ON_DESTROY), m_fixFingerTimer(Timer::CANCEL_ON_DESTROY), m_auditFingerTimer(Timer::CANCEL_ON_DESTROY) {
    RandomVariable random;
    SeedManager::SetSeed(time(NULL));
    random = UniformVariable(0x00000000, 0xFFFFFFFF);
    m_currentTransactionId = random.GetInteger();

}

PennChord::~PennChord() {

}

void
PennChord::DoDispose() {
    StopApplication();
    PennApplication::DoDispose();
}

void
PennChord::StartApplication(void) {
    if (m_socket == 0) {
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        m_socket = Socket::CreateSocket(GetNode(), tid);
        InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), m_appPort);
        m_socket->Bind(local);
        m_socket->SetRecvCallback(MakeCallback(&PennChord::RecvMessage, this));
    }

    // Configure timers
    m_auditPingsTimer.SetFunction(&PennChord::AuditPings, this);
    m_fixFingerTimer.SetFunction(&PennChord::FixFingers, this);
    m_auditFingerTimer.SetFunction(&PennChord::AuditFingers, this);
    // Start timers
    m_auditPingsTimer.Schedule(m_pingTimeout);

    NormalVariable interval = NormalVariable (m_fixFingerInterval.GetMilliSeconds (), 500);
    //m_fixFingerTimer.Schedule (MilliSeconds (interval.GetValue ()));
    m_fixFingerTimer.Schedule(m_fixFingerInterval);

    m_auditFingerTimer.Schedule(m_auditFingerInterval);


    // Stores hash into location
    uint8_t ip_string[4];
    m_local.Serialize(ip_string);
    SHA1((const unsigned char *) ip_string, sizeof (ip_string), m_info.location);
    m_info.address = m_local;
    m_remoteNodeSelf = Create<remote_node> (m_info, m_socket, m_appPort);
    PopulateFingerLocationList();
    NodeInfo b;
    b.address = Ipv4Address("0.0.0.0");
    m_predecessor = Create<remote_node> (b, m_socket, m_appPort);
    m_successor = Create<remote_node> (b, m_socket, m_appPort);




}

void
PennChord::StopApplication(void) {

    // Close socket
    if (m_socket) {
        m_socket->Close();
        m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket> > ());
        m_socket = 0;
    }
    // Cancel timers
    m_auditPingsTimer.Cancel();
    m_fixFingerTimer.Cancel();
    m_auditFingerTimer.Cancel();

    m_pingTracker.clear();
}

void
PennChord::PopulateFingerLocationList ()
{
  for (uint8_t i = 0; i < (SHA_DIGEST_LENGTH * 8); i++)
    {
      // Make copy
      unsigned char location[SHA_DIGEST_LENGTH];
      memcpy(location, m_info.location, SHA_DIGEST_LENGTH);
      // Add power of two
      AddPowerOfTwo (location, i);
      m_fingerLocationList[i] = (location);
    }
}

void
PennChord::AddPowerOfTwo (unsigned char location[], uint16_t powerOfTwo)
{
  uint8_t powZero = 0x01;
  // Find the position of byte in location
  uint8_t position = powerOfTwo / 8;
  NS_ASSERT (position < SHA_DIGEST_LENGTH);
  uint8_t shift = powerOfTwo % 8;
  uint8_t prevVal = location[position];
  // Add power
  location[position] = location[position] + (powZero << shift);
  // Take care of carry
  while ((location[position] < prevVal) && (position < (SHA_DIGEST_LENGTH - 1)))
    {
      position++;
      prevVal = location[position];
      location[position] = location[position] + 0x01;
  }
}

void
PennChord::ProcessCommand(std::vector<std::string> tokens) {
    std::vector<std::string>::iterator iterator = tokens.begin();
    std::string command = *iterator;


    if (command == "join" || command == "JOIN") {
        iterator++;
        std::string landmark = *iterator;

        std::stringstream ss;
        ss << m_node->GetId();
        std::string m_id = ss.str();
        Ipv4Address ldmk = ResolveNodeIpAddress(landmark);

        //CHORD_LOG("ldmk IP: " << ldmk << ", m_local: " << m_local);
        // CHORD_LOG(m_id << " is the ID and " << landmark << " is the landmark" << std::endl);

        if (ldmk == m_local) {
          CreateOverlay();
        } else {
            JoinOverlay(ldmk);
        }
    } else if (command == "leave" || command == "LEAVE") {
        LeaveInitiate();
    } else if (command == "ringstate" || command == "RINGSTATE") {
        PrintInfo();
        GetNextTransactionId();
        PennChordMessage::PennChordPacket chordPacket = m_successor->RingDebug(m_info, 1, m_currentTransactionId);
        Ptr<PennChordTransaction> transaction = Create<PennChordTransaction> (MakeCallback(&PennChord::procRING_DBG, this), m_currentTransactionId, chordPacket, m_successor, m_debugTimeout, m_maxRequestRetries);
        m_chordTracker[m_currentTransactionId] = transaction;
        EventId requestTimeoutId = Simulator::Schedule(transaction->m_requestTimeout, &PennChord::HandleRequestTimeout, this, m_currentTransactionId);
        transaction->m_requestTimeoutEventId = requestTimeoutId;
        //m_successor->RingDebug(m_info, 1, m_currentTransactionId);
    }


}

void
PennChord::SendPing(Ipv4Address destAddress, std::string pingMessage) {
    if (destAddress != Ipv4Address::GetAny()) {
        uint32_t transactionId = GetNextTransactionId();
        CHORD_LOG("Sending PING_REQ to IP: " << destAddress << " Message: " << pingMessage << " transactionId: " << transactionId);
        Ptr<PingRequest> pingRequest = Create<PingRequest> (transactionId, Simulator::Now(), destAddress, pingMessage);
        // Add to ping-tracker
        m_pingTracker.insert(std::make_pair(transactionId, pingRequest));
        Ptr<Packet> packet = Create<Packet> ();
        PennChordMessage message = PennChordMessage(PennChordMessage::PING_REQ, transactionId);
        message.SetPingReq(pingMessage);
        packet->AddHeader(message);
        m_socket->SendTo(packet, 0, InetSocketAddress(destAddress, m_appPort));
    } else {
        // Report failure   
        m_pingFailureFn(destAddress, pingMessage);
    }
}

void
PennChord::RecvMessage(Ptr<Socket> socket) {
    Address sourceAddr;
    Ptr<Packet> packet = socket->RecvFrom(sourceAddr);
    InetSocketAddress inetSocketAddr = InetSocketAddress::ConvertFrom(sourceAddr);
    Ipv4Address sourceAddress = inetSocketAddr.GetIpv4();
    uint16_t sourcePort = inetSocketAddr.GetPort();
    PennChordMessage message;
    packet->RemoveHeader(message);

    switch (message.GetMessageType()) {
        case PennChordMessage::PING_REQ:
            ProcessPingReq(message, sourceAddress, sourcePort);
            break;
        case PennChordMessage::PING_RSP:
            ProcessPingRsp(message, sourceAddress, sourcePort);
            break;
        case PennChordMessage::CHOR_PAC:
            ProcessChordMessage(message, sourceAddress, sourcePort);
            break;
        default:
            ERROR_LOG("Unknown Message Type!");
            break;
    }
}

void
PennChord::ProcessPingReq(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort) {

    // Using IP address for use on multiple real machines
    CHORD_LOG("Received PING_REQ, From IP: " << sourceAddress << ", Message: " << message.GetPingReq().pingMessage);
    // Send Ping Response
    PennChordMessage resp = PennChordMessage(PennChordMessage::PING_RSP, message.GetTransactionId());
    resp.SetPingRsp(message.GetPingReq().pingMessage);
    Ptr<Packet> packet = Create<Packet> ();
    packet->AddHeader(resp);
    m_socket->SendTo(packet, 0, InetSocketAddress(sourceAddress, sourcePort));
    // Send indication to application layer
    m_pingRecvFn(sourceAddress, message.GetPingReq().pingMessage);
}

void
PennChord::ProcessPingRsp(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort) {
    // Remove from pingTracker
    std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
    iter = m_pingTracker.find(message.GetTransactionId());
    if (iter != m_pingTracker.end()) {
        CHORD_LOG("Received PING_RSP, From IP: " << sourceAddress << ", Message: " << message.GetPingRsp().pingMessage);
        m_pingTracker.erase(iter);
        // Send indication to application layer
        m_pingSuccessFn(sourceAddress, message.GetPingRsp().pingMessage);
    } else {
        DEBUG_LOG("Received invalid PING_RSP!");
    }
}

void
PennChord::AuditPings() {
    std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
    for (iter = m_pingTracker.begin(); iter != m_pingTracker.end();) {
        Ptr<PingRequest> pingRequest = iter->second;
        if (pingRequest->GetTimestamp().GetMilliSeconds() + m_pingTimeout.GetMilliSeconds() <= Simulator::Now().GetMilliSeconds()) {
            DEBUG_LOG("Ping expired. Message: " << pingRequest->GetPingMessage() << " Timestamp: " << pingRequest->GetTimestamp().GetMilliSeconds() << " CurrentTime: " << Simulator::Now().GetMilliSeconds());
            // Remove stale entries
            m_pingTracker.erase(iter++);
            // Send indication to application layer
            m_pingFailureFn(pingRequest->GetDestinationAddress(), pingRequest->GetPingMessage());
        } else {
            ++iter;
        }
    }
    // Rechedule timer
    m_auditPingsTimer.Schedule(m_pingTimeout);
}

uint32_t
PennChord::GetNextTransactionId() {
    if (m_currentTransactionId == ~0) {
        m_currentTransactionId = 0;
    } else {
        m_currentTransactionId++;
    }
    return m_currentTransactionId;
}

void
PennChord::StopChord() {
  //Print results
  float avg_lookups = 0.0;
  if(num_lookups != 0){
    avg_lookups = (float)num_hops/num_lookups;
  }

  //  CHORD_LOG("Average hop count: " << avg_lookups << " " << num_hops <<" "<< num_lookups << std::endl);
  CHORD_LOG("Average hop count: " << avg_lookups);
  
  // print finger table
  //DEBUG_LOG("Finger Table" << " SHA_DIGEST_LENGTH: " << SHA_DIGEST_LENGTH << " figerTable size: " << m_fingerTable.size());
  for (std::map<uint8_t, Ptr<remote_node> >::iterator iter = m_fingerTable.begin(); iter != m_fingerTable.end(); iter++)  {
    //DEBUG_LOG("Finger Entry: " << iter->first << " : " << iter->second->m_info.address);
  }

    StopApplication();
}

void
PennChord::SetPingSuccessCallback(Callback <void, Ipv4Address, std::string> pingSuccessFn) {
    m_pingSuccessFn = pingSuccessFn;
}

void
PennChord::SetPingFailureCallback(Callback <void, Ipv4Address, std::string> pingFailureFn) {
    m_pingFailureFn = pingFailureFn;
}

void
PennChord::SetPingRecvCallback(Callback <void, Ipv4Address, std::string> pingRecvFn) {
    m_pingRecvFn = pingRecvFn;
}

void PennChord::SetLookupSuccessCallback(Callback<void, uint8_t*, uint8_t, Ipv4Address, uint32_t> lookupSuccessFn) {
    m_lookupSuccessFn = lookupSuccessFn;
}

void PennChord::SetLookupFailureCallback(Callback<void, uint8_t*, uint8_t, uint32_t> lookupFailureFn) {
    m_lookupFailureFn = lookupFailureFn;
}

// TODO Implement

void PennChord::JoinOverlay(Ipv4Address landmark) {
    //CHORD_LOG("Joining Overlay at " << landmark << std::endl);
    //    cout << "Hash ";
    //    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
    //        cout << std::hex << (int) m_info.location[i];
    //    }
    //    cout << std::endl << std::dec;

    joined = 1;
    NodeInfo info;
    info.address = landmark;
    m_landmark = Create<remote_node> (info, m_socket, m_appPort);
    // update TransactionId
    GetNextTransactionId();
    // Sends a request for the location of the landmark
    PennChordMessage::PennChordPacket chordPacket = m_landmark->find_successor(m_info, m_info.location, m_currentTransactionId);
    Ptr<PennChordTransaction> transaction = Create<PennChordTransaction> (MakeCallback(&PennChord::procRSP_SUC, this), m_currentTransactionId, chordPacket, m_landmark, m_requestTimeout, m_maxRequestRetries);
    m_chordTracker[m_currentTransactionId] = transaction;
    EventId requestTimeoutId = Simulator::Schedule(transaction->m_requestTimeout, &PennChord::HandleRequestTimeout, this, m_currentTransactionId);
    transaction->m_requestTimeoutEventId = requestTimeoutId;

    // Configure timers
    m_stabilizeTimer.SetFunction(&PennChord::stabilize, this);
    // Start timers
    m_stabilizeTimer.Schedule(m_stabilizeFreq);

}

uint32_t PennChord::Lookup(unsigned char location[]) {
    // Sends a request for the location of the landmark
    inLookup = true;
    num_lookups++;
    GetNextTransactionId();
    CHORD_LOG("\nLookupIssue <current:" << strHash(m_info.location) << ", target: " << strHash(location) << ">");
    PennChordMessage::PennChordPacket chordPacket = m_remoteNodeSelf->find_lookup(m_info, location, m_currentTransactionId);
    Ptr<PennChordTransaction> transaction = Create<PennChordTransaction> (MakeCallback(&PennChord::procRSP_LOOK, this), m_currentTransactionId, chordPacket, m_remoteNodeSelf, m_requestTimeout, m_maxRequestRetries);
    m_chordTracker[m_currentTransactionId] = transaction;
    EventId requestTimeoutId = Simulator::Schedule(transaction->m_requestTimeout, &PennChord::HandleRequestTimeout, this, m_currentTransactionId);
    transaction->m_requestTimeoutEventId = requestTimeoutId;
    return m_currentTransactionId;
}

void PennChord::CreateOverlay() {
    //CHORD_LOG("Creating Overlay" << std::endl);

    //    cout << "Hash ";
    //    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
    //        cout << std::hex << (int) m_info.location[i];
    //    }
    //    cout << std::endl << std::dec;

    joined = 2;
    m_successor = Create<remote_node> (m_info, m_socket, m_appPort);

    // TODO Use an enum? Find a better way
    NodeInfo blank;
    blank.address = Ipv4Address("0.0.0.0");
    Ptr<remote_node> blank_node = Create<remote_node> (blank, m_socket, m_appPort);

    // set predecessor to self as well as successor
    m_predecessor = blank_node;

    // Configure timers
    m_stabilizeTimer.SetFunction(&PennChord::stabilize, this);
    // Start timers
    m_stabilizeTimer.Schedule(m_stabilizeFreq);


}

// TODO
// Clean up remote note instantiation where location is unknown
// Fix requestee value

void PennChord::ProcessChordMessage(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort) {

    if (joined == 0) {
        return;
    }
    PennChordMessage::PennChordPacket p = message.GetChordPacket();
    if(p.requestee.IsEqual("10.0.0.1") && !p.originator.address.IsEqual("10.0.0.1")){
//      p.Print(std::cout);  
    }
    
    //    DEBUG_LOG("Packet Received");

    map<uint32_t, Ptr<PennChordTransaction> >::iterator callback_pair = m_chordTracker.find(p.m_transactionId);
    if (callback_pair != m_chordTracker.end() && p.originator.address == m_info.address && p.m_resolved == true) {
        callback_pair->second->m_replyProcFn(p, sourceAddress, sourcePort);
        m_chordTracker.erase(callback_pair);
        return;

    } else {

        switch (p.m_messageType) {
            case (PennChordMessage::PennChordPacket::REQ_PRE):
            {
                procREQ_PRE(p, sourceAddress, sourcePort);
                break;
            }
            case (PennChordMessage::PennChordPacket::RSP_PRE):
            {
                procRSP_PRE(p, sourceAddress, sourcePort);
                break;
            }
            case (PennChordMessage::PennChordPacket::REQ_SUC):
            {
                procREQ_SUC(p, sourceAddress, sourcePort);
                break;
            }
            case (PennChordMessage::PennChordPacket::RSP_SUC):
            {
                // being handled through callbacks
                //procRSP_SUC(p, sourceAddress, sourcePort);
                break;
            }
            case (PennChordMessage::PennChordPacket::REQ_NOT):
            {
                procREQ_NOT(p, sourceAddress, sourcePort);
                break;
            }
            case (PennChordMessage::PennChordPacket::REQ_CP):
            {
                procREQ_CP(p, sourceAddress, sourcePort);
                break;
            }
            case (PennChordMessage::PennChordPacket::RSP_CP):
            {
                procRSP_CP(p, sourceAddress, sourcePort);
                break;
            }
            case (PennChordMessage::PennChordPacket::RING_DBG):
            {
                procRING_DBG(p, sourceAddress, sourcePort);
                break;
            }
            case (PennChordMessage::PennChordPacket::LEAVE_SUC):
            {
                procLEAVE_SUC(p, sourceAddress, sourcePort);
                break;
            }
            case (PennChordMessage::PennChordPacket::LEAVE_PRED):
            {
                procLEAVE_PRED(p, sourceAddress, sourcePort);
                break;
            }
            case (PennChordMessage::PennChordPacket::LEAVE_CONF):
            {
                procLEAVE_CONF(p, sourceAddress, sourcePort);
                break;
            }
            case (PennChordMessage::PennChordPacket::REQ_LOOK):
            {
                procREQ_LOOK(p, sourceAddress, sourcePort);
                break;
            }
            case (PennChordMessage::PennChordPacket::REQ_LOOKUP):
            {
                procREQ_LOOKUP(p, sourceAddress, sourcePort);
                break;
            }
            case (PennChordMessage::PennChordPacket::RSP_LOOK):
            {
                // being handled by callback
                //procRSP_LOOK(p, sourceAddress, sourcePort);
                break;
            }
            case (PennChordMessage::PennChordPacket::REQ_FINGER):
            {
                procREQ_FINGER(p, sourceAddress, sourcePort);
                break;
            }
            case (PennChordMessage::PennChordPacket::RSP_FINGER):
            {
                procRSP_FINGER(p, sourceAddress, sourcePort);
                break;
            }
            default:
                cout << "Invalid Message Type";
        }
        }
    }

void PennChord::stabilize() {
    //PrintInfo();
    m_successor->closest_preceeding(m_info);
    m_stabilizeTimer.Schedule(m_stabilizeFreq);
}

void PennChord::LeaveInitiate() {
    //CHORD_LOG("Leaving Ring");
    m_stabilizeTimer.Cancel();
    // update TransactionId
    GetNextTransactionId();
    // Sends a request for the location of the landmark
    PennChordMessage::PennChordPacket chordPacket = m_predecessor->Leave_Suc(m_info, m_successor->m_info, m_currentTransactionId);
    Ptr<PennChordTransaction> transaction = Create<PennChordTransaction> (MakeCallback(&PennChord::procLEAVE_SUC, this), m_currentTransactionId, chordPacket, m_predecessor, m_debugTimeout, m_maxRequestRetries);
    m_chordTracker[m_currentTransactionId] = transaction;
    EventId requestTimeoutId = Simulator::Schedule(transaction->m_requestTimeout, &PennChord::HandleRequestTimeout, this, m_currentTransactionId);
    transaction->m_requestTimeoutEventId = requestTimeoutId;


    //m_predecessor->Leave_Suc(m_info, m_successor->m_info, m_currentTransactionId);
}

void PennChord::LeaveOverlay() {
    // CHORD_LOG("Leaving Overlay");
    NodeInfo blank;
    blank.address = Ipv4Address("0.0.0.0");
    Ptr<remote_node> blank_node = Create<remote_node> (blank, m_socket, m_appPort);
    NodeInfo blank2;
    blank.address = Ipv4Address("0.0.0.0");
    Ptr<remote_node> blank_node2 = Create<remote_node> (blank2, m_socket, m_appPort);
    NodeInfo blank3;
    blank.address = Ipv4Address("0.0.0.0");
    Ptr<remote_node> blank_node3 = Create<remote_node> (blank3, m_socket, m_appPort);
    m_landmark = blank_node;
    m_predecessor = blank_node2;
    m_successor = blank_node3;

    // Cancel timers
    // m_stabilizeTimer.Cancel();

}


void PennChord::HandleRequestTimeout(uint32_t transactionId) {
    // Find transaction
    Ptr<PennChordTransaction> chordTransaction = m_chordTracker [transactionId];
    if (!chordTransaction) {
        // Transaction does not exist
        return;
    }
    chordTransaction->m_retries++;
    // Retransmit and reschedule if needed
    if (chordTransaction->m_retries > chordTransaction->m_maxRetries) {
        // Report failure
        if (chordTransaction->m_chordPacket.m_messageType == PennChordMessage::PennChordPacket::REQ_LOOKUP) {
            CHORD_LOG("Lookup failed for location " << strHash(chordTransaction->m_chordPacket.lookupLocation));
            if (!m_lookupFailureFn.IsNull()) {
                m_lookupFailureFn(chordTransaction->m_chordPacket.lookupLocation, SHA_DIGEST_LENGTH, chordTransaction->m_transactionId);
                m_chordTracker.erase(transactionId);
            }
        }
        else if (chordTransaction->m_chordPacket.m_messageType == PennChordMessage::PennChordPacket::REQ_SUC)  {
          CHORD_LOG("Request Successor failed");
        }
        else if (chordTransaction->m_chordPacket.m_messageType == PennChordMessage::PennChordPacket::RING_DBG)  {
          CHORD_LOG("Ring Debug failed");
        }
        else if (chordTransaction->m_chordPacket.m_messageType == PennChordMessage::PennChordPacket::LEAVE_SUC)  {
          CHORD_LOG("Leave Successor failed");
        }
        return;
    }

    else {
        // Retransmit
        //CHORD_LOG ("Retransmission Req\n" << chordPacket);
        chordTransaction->m_remoteNode->SendRPC(chordTransaction->m_chordPacket);
        // Reschedule
        // Start transaction timer
        EventId requestTimeoutId = Simulator::Schedule(chordTransaction->m_requestTimeout, &PennChord::HandleRequestTimeout, this, transactionId);
        chordTransaction->m_requestTimeoutEventId = requestTimeoutId;
    }
}

void PennChord::PrintInfo() {
    //    cout << "Hash ";
    //    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
    //        cout << std::hex << (int) m_info.location[i];
    //    }
    //    cout << std::endl << std::dec;
    //CHORD_LOG("\nRingState: " << ReverseLookup(m_local) << " Predecessor: " << ReverseLookup(m_predecessor.m_info.address) << " Successor: " << ReverseLookup(m_successor.m_info.address));

    CHORD_LOG("\nRingState<" << strHash(m_info.location) << ">: Pred<"
            << ReverseLookup(m_predecessor->m_info.address) << ", " << strHash(m_predecessor->m_info.location)
            << ">,Succ<" << ReverseLookup(m_successor->m_info.address) <<
            ", " << strHash(m_successor->m_info.location) << ">"
            );

}

void PennChord::FixFingers() {
  for (std::map<uint8_t, uint8_t*>::iterator fingerIter = m_fingerLocationList.begin (); fingerIter != m_fingerLocationList.end (); fingerIter++)
  {
    uint8_t fingerNum = fingerIter->first;
    m_fingerReceipt[fingerNum] = false;
    uint8_t *fingerLocation = fingerIter->second;
    // Do not lookup local locations
    if (RangeCompare(m_predecessor->m_info.location, fingerLocation, m_info.location))
      {
        continue;
      }
    // Do not lookup fingers between successor and this node
    if (RangeCompare(m_info.location, fingerLocation, m_successor->m_info.location))
      {
        m_fingerTable[fingerNum] = m_successor;
        continue;
      }
    GetNextTransactionId();
    PennChordMessage::PennChordPacket chordPacket = m_successor->find_finger(m_info, fingerLocation, m_currentTransactionId, fingerNum);
  }
  NormalVariable interval = NormalVariable (m_fixFingerInterval.GetMilliSeconds (), 500);
  m_fixFingerTimer.Schedule (MilliSeconds (interval.GetValue ()));
  //m_fixFingerTimer.Schedule(m_fixFingerInterval);
}

void PennChord::AuditFingers() {
  for (std::map<uint8_t, bool>::iterator fingerIter = m_fingerReceipt.begin (); fingerIter != m_fingerReceipt.end (); fingerIter++)
  {
    uint8_t fingerNum = fingerIter->first;
    if (fingerIter->second == false)  {
      m_fingerTable.erase(fingerNum);
    }
  }
  // peridicity same as fix finger but staggered
  m_auditFingerTimer.Schedule(m_fixFingerInterval);
}

Ptr<remote_node> PennChord::FindFinger(uint8_t location[]) {
  // stop at largest finger
  Ptr<remote_node> fingerNode;
  for (uint8_t fingerNum = 0; fingerNum != SHA_DIGEST_LENGTH * 8; fingerNum++) {
    if (m_fingerTable.find(fingerNum) != m_fingerTable.end())  {
      if (RangeCompare(m_info.location, m_fingerTable[fingerNum]->m_info.location, location)) {
        fingerNode = m_fingerTable[fingerNum];
      }
      else  {
        break;
      }
    }
  }
  return fingerNode;
}

void PennChord::SetJoinCallback(Callback<void> cb) {
    m_joinedCallback = cb;
}

NodeInfo PennChord::getSuccessor() {
    return m_successor->m_info;
}

NodeInfo PennChord::getPredecessor() {
    return m_predecessor->m_info;
}

string strHash(unsigned char *hash) {
    stringstream s;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
      if (i > 0 && (i%2 == 0)) {
        s << ".";
      }
        s << std::hex << (int) hash[i];
    }
    s << std::dec;
    return s.str();
}

bool RangeCompare(unsigned char *low, unsigned char *mid, unsigned char *high) {
    string me = string((const char *) mid);
    string pred = string((const char *) low);
    string suc = string((const char *) high);

    // is greater than 0 if me is larger
    int pre_cmp = me.compare(pred);
    // is less than 0 if me is smaller
    int cur_cmp = me.compare(suc);
    // is less than 0 if suc is less than pred
    int both_cmp = suc.compare(pred);

    //    DEBUG_LOG("RC both_cmp = " << both_cmp << endl);

    if (both_cmp == 0) {
        return 1;
    } else if (both_cmp > 0) {
        if (pre_cmp <= 0) {
            return 0;
        } else if (cur_cmp > 0) {
            return 0;
        } else if (cur_cmp < 0) {
            return 1;
        } else {
            return 2;
        }
    } else if (both_cmp < 0) {
        //    DEBUG_LOG("RC " << pre_cmp << " pre and post " << cur_cmp << endl);
        if (cur_cmp == 0) {
            return 2;
        } else if (pre_cmp > 0 || cur_cmp < 0) {
            return 1;
        } else if (pre_cmp < 0 || cur_cmp > 0) {
            return 0;
        }
    } else {
        return 2;
    }

}

void PrintHash(unsigned char *hash, std::ostream &os) {
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        os << std::hex << (int) hash[i];
    }
    os << std::endl << std::dec;
}
