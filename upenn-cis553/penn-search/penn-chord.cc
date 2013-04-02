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

            .AddAttribute("StabilizeFreq",
            "Frequency to Update Successor",
            TimeValue(Seconds(15)),
            MakeTimeAccessor(&PennChord::m_stabilizeFreq),
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

    NodeInfo b;
    b.address = Ipv4Address("0.0.0.0");
    m_predecessor = remote_node(b, m_socket, m_appPort);
    m_successor = remote_node(b, m_socket, m_appPort);




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


    if (command == "join" || command == "JOIN") {
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
    } else if (command == "leave" || command == "LEAVE") {
        LeaveInitiate();
    } else if (command == "ringstate" || command == "RINGSTATE") {
        PrintInfo();
        m_successor.RingDebug(m_info);
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
    CHORD_LOG("Joining Overlay at " << landmark << std::endl);

    cout << "Hash ";
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        cout << std::hex << (int) m_info.location[i];
    }
    cout << std::endl << std::dec;


    NodeInfo info;
    info.address = landmark;
    remote_node s(info, m_socket, m_appPort);
    m_landmark = s;
    // Sends a request for the location of the landmark
    m_landmark.find_successor(m_info);

    // Configure timers
    m_stabilizeTimer.SetFunction(&PennChord::stabilize, this);
    // Start timers
    m_stabilizeTimer.Schedule(m_stabilizeFreq);

}

void PennChord::CreateOverlay() {
    CHORD_LOG("Creating Overlay" << std::endl);

    cout << "Hash ";
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        cout << std::hex << (int) m_info.location[i];
    }
    cout << std::endl << std::dec;

    remote_node i_node(m_info, m_socket, m_appPort);
    m_successor = i_node;

    // TODO Use an enum? Find a better way
    NodeInfo blank;
    blank.address = Ipv4Address("0.0.0.0");
    remote_node blank_node(blank, m_socket, m_appPort);

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
    PennChordMessage::PennChordPacket p = message.GetChordPacket();

    DEBUG_LOG("Packet Received");

    map<uint32_t, Callback<void, PennChordMessage::PennChordPacket, Ipv4Address, uint16_t> >::iterator callback_pair = m_chordTracker.find(p.m_transactionId);
    if (callback_pair != m_chordTracker.end()) {
        callback_pair->second(p, sourceAddress, sourcePort);

    } else {

        switch (p.m_messageType) {
            case (PennChordMessage::PennChordPacket::REQ_SUC):
            {
                procREQ_SUC(p, sourceAddress, sourcePort);
                break;
            }
            case (PennChordMessage::PennChordPacket::RSP_SUC):
            {
                procRSP_SUC(p, sourceAddress, sourcePort);
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
            case (PennChordMessage::PennChordPacket::RSP_LOOK):
            {
                procRSP_LOOK(p, sourceAddress, sourcePort);
                break;
            }
            default:
                cout << "Invalid Message Type";
        }
    }
}




void PennChord::stabilize() {
    //PrintInfo();
    m_successor.closest_preceeding(m_info);
    m_stabilizeTimer.Schedule(m_stabilizeFreq);
}

void PennChord::LeaveInitiate() {
    m_predecessor.Leave_Suc(m_info, m_successor.m_info);
}

void PennChord::LeaveOverlay() {
    CHORD_LOG("Leaving Overlay");
    NodeInfo blank;
    blank.address = Ipv4Address("0.0.0.0");
    remote_node blank_node(blank, m_socket, m_appPort);
    m_landmark = blank_node;
    m_predecessor = blank_node;
    m_successor = blank_node;

    // Cancel timers
    m_stabilizeTimer.Cancel();

}

bool PennChord::RangeCompare(u_char *low, u_char *mid, u_char *high) {
    string p_hash((const char *) mid);
    int pre_cmp = p_hash.compare(string((const char *) low));
    int cur_cmp = p_hash.compare(string((const char *) high));


    DEBUG_LOG("RC " << pre_cmp << " pre and post " << cur_cmp << endl);
    DEBUG_LOG("RC " << (pre_cmp > 0 && cur_cmp <= 0) << endl);

    // For open interval
    if (pre_cmp > 0 && cur_cmp < 0) {
        return 1;
    }// For half closed interval
    else if (pre_cmp > 0 && cur_cmp <= 0) {
        return 2;
    }// Wrap around
    else if (pre_cmp > 0 && pre_cmp < cur_cmp) {
        return 3;
    } else {
        // Check to see if only single node
        return (string((const char *) low).compare(string((const char *) high)) == 0);
    }
}

void PennChord::PrintInfo() {
    //    cout << "Hash ";
    //    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
    //        cout << std::hex << (int) m_info.location[i];
    //    }
    //    cout << std::endl << std::dec;
    CHORD_LOG("\nRING DEBUG -- Self: " << m_local << " Predecessor: " << m_predecessor.m_info.address << " Successor: " << m_successor.m_info.address);
}
