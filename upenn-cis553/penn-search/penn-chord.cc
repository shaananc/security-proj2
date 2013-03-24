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

// TODO Fill in all functions
// Clear up params
// Change remote_node usage

#include "penn-chord.h"

#include "ns3/random-variable.h"
#include "ns3/inet-socket-address.h"
#include "NodeInfo.h"

#include <openssl/sha.h>

using namespace ns3;

class remote_node;

TypeId
PennChord::GetTypeId() {
    static TypeId tid = TypeId("PennChord")
            .SetParent<PennApplication> ()
            .AddConstructor<PennChord> ()
            .AddAttribute("AppPort",
            "Listening port for Application",
            UintegerValue(10001),
            MakeUintegerAccessor(&PennChord::m_appPort),
            MakeUintegerChecker<uint16_t> ())
            .AddAttribute("PingTimeout",
            "Timeout value for PING_REQ in milliseconds",
            TimeValue(MilliSeconds(2000)),
            MakeTimeAccessor(&PennChord::m_pingTimeout),
            MakeTimeChecker())
            ;
    return tid;
}

PennChord::PennChord()
: m_auditPingsTimer(Timer::CANCEL_ON_DESTROY) {
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
    // Start timers
    m_auditPingsTimer.Schedule(m_pingTimeout);


    // Stores hash into location
    uint8_t ip_string[4];
    m_local.Serialize(ip_string);
    SHA1((const u_char *) ip_string, sizeof (ip_string), m_info.location);
    m_info.address = m_local;


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

    m_pingTracker.clear();
}

void
PennChord::ProcessCommand(std::vector<std::string> tokens) {
    std::vector<std::string>::iterator iterator = tokens.begin();
    std::string command = *iterator;


    if (command == "join") {
        iterator++;
        std::string landmark = *iterator;

        std::stringstream ss;
        ss << m_node->GetId();
        std::string m_id = ss.str();

        CHORD_LOG(m_id << " is the ID and " << landmark << " is the landmark" << std::endl);

        if (landmark == m_id) {
            CreateOverlay();
        } else {
            JoinOverlay(ResolveNodeIpAddress(landmark));
        }
    } else if (command == "leave") {
        LeaveOverlay();
    } else if (command == "ringstate") {

    }


}

void
PennChord::SendPing(Ipv4Address destAddress, std::string pingMessage) {
    if (destAddress != Ipv4Address::GetAny()) {
        uint32_t transactionId = GetNextTransactionId();
        CHORD_LOG("Sending PING_REQ to Node: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << pingMessage << " transactionId: " << transactionId);
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
            //TODO process chord reply
            // Process in Penn-Chord
            break;
        case PennChordMessage::RING_DBG:
            RingstateDebug();
        default:
            ERROR_LOG("Unknown Message Type!");
            break;
    }
}

void
PennChord::ProcessPingReq(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort) {

    // Use reverse lookup for ease of debug
    std::string fromNode = ReverseLookup(sourceAddress);
    CHORD_LOG("Received PING_REQ, From Node: " << fromNode << ", Message: " << message.GetPingReq().pingMessage);
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
        std::string fromNode = ReverseLookup(sourceAddress);
        CHORD_LOG("Received PING_RSP, From Node: " << fromNode << ", Message: " << message.GetPingRsp().pingMessage);
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
    return m_currentTransactionId++;
}

void
PennChord::StopChord() {
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

// TODO Implement

void PennChord::JoinOverlay(Ipv4Address landmark) {
    CHORD_LOG("Joining Overlay" << std::endl);
    NodeInfo info;
    info.address = landmark;
    remote_node s(info, m_socket, m_appPort);
    m_landmark = s;
    // Sends a request for the location of the landmark
    m_landmark.find_successor(m_info);

}

void PennChord::CreateOverlay() {
    CHORD_LOG("Creating Overlay" << std::endl);


    remote_node i_node(m_info, m_socket, m_appPort);
    m_sucessor = i_node;

    // TODO Use an enum? Find a better way
    NodeInfo blank;
    blank.address = Ipv4Address("0.0.0.0");
    remote_node blank_node(blank, m_socket, m_appPort);

    m_predecessor = blank_node;




}

// TODO
// Clean up remote note instantiation where location is unknown
// Fix requestee value

void PennChord::ProcessChordMessage(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort) {
    PennChordMessage::PennChordPacket p = message.GetChordPacket();
    CHORD_LOG(m_local << " is my ip");
    p.Print(std::cout);
    std::cout << "\n\n\n";
    if (p.m_messageType == PennChordMessage::PennChordPacket::REQ_SUC) {
        // put into a function
        string p_hash((const char *)p.originator.location);
        int pre_cmp = p_hash.compare(string((const char *)m_predecessor.m_info.location));
        int cur_cmp = p_hash.compare(string((const char *)m_info.location));
        // TODO TEST THIS URGENT
        if (m_predecessor.m_info.address.IsEqual(Ipv4Address("0.0.0.0")) ||
                 (pre_cmp < 0 && cur_cmp <= 0)
                ) {
            remote_node blank_node(p.originator, m_socket, m_appPort);
            blank_node.reply_successor(m_sucessor.m_info, p.requestee, p.originator);
        }


    } else if (p.m_messageType == PennChordMessage::PennChordPacket::RSP_SUC) {
        m_sucessor.m_info = p.m_result;
        // Make callbacks
        vector<Callback<void> >::iterator itr;
        for (itr = m_successor_callbacks.begin(); itr != m_successor_callbacks.end(); itr++) {
            (*itr)();
        }
        m_successor_callbacks.clear();
    }

}

void PennChord::LeaveOverlay() {

}


// Print self then send ringstate message to next node

void PennChord::RingstateDebug() {

}