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
            TimeValue(MilliSeconds(900)),
            MakeTimeAccessor(&PennChord::m_stabilizeFreq),
            MakeTimeChecker())

            .AddAttribute("RequestTimeout",
            "Timeout value for request retransmission in milli seconds",
            TimeValue(MilliSeconds(2000)),
            MakeTimeAccessor(&PennChord::m_requestTimeout),
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
: m_auditPingsTimer(Timer::CANCEL_ON_DESTROY) {
    RandomVariable random;
    SeedManager::SetSeed(time(NULL));
    random = UniformVariable(0x00000000, 0xFFFFFFFF);
    m_currentTransactionId = random.GetInteger();

    num_hops = 0;
    num_lookups = 0;

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
    SHA1((const unsigned char *) ip_string, sizeof (ip_string), m_info.location);
    m_info.address = m_local;
    m_remoteNodeSelf = Create<remote_node> (m_info, m_socket, m_appPort);

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

        //CHORD_LOG(m_id << " is the ID and " << landmark << " is the landmark" << std::endl);

        if (landmark == m_id) {
            CreateOverlay();
        } else {
            JoinOverlay(ResolveNodeIpAddress(landmark));
        }
    } else if (command == "leave" || command == "LEAVE") {
        LeaveInitiate();
    } else if (command == "ringstate" || command == "RINGSTATE") {
        PrintInfo();
        m_successor->RingDebug(m_info, 1);
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
    CHORD_LOG("Joining Overlay at " << landmark << std::endl);
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
    GetNextTransactionId();
    PennChordMessage::PennChordPacket chordPacket = m_remoteNodeSelf->find_successor(m_info, location, m_currentTransactionId);
    Ptr<PennChordTransaction> transaction = Create<PennChordTransaction> (MakeCallback(&PennChord::procRSP_LOOK, this), m_currentTransactionId, chordPacket, m_remoteNodeSelf, m_requestTimeout, m_maxRequestRetries);
    m_chordTracker[m_currentTransactionId] = transaction;
    EventId requestTimeoutId = Simulator::Schedule(transaction->m_requestTimeout, &PennChord::HandleRequestTimeout, this, m_currentTransactionId);
    transaction->m_requestTimeoutEventId = requestTimeoutId;
    return m_currentTransactionId;
}

void PennChord::CreateOverlay() {
    CHORD_LOG("Creating Overlay" << std::endl);

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

    //    DEBUG_LOG("Packet Received");

    map<uint32_t, Ptr<PennChordTransaction> >::iterator callback_pair = m_chordTracker.find(p.m_transactionId);
    if (callback_pair != m_chordTracker.end() && p.originator.address == m_info.address && p.m_resolved == true) {
        callback_pair->second->m_replyProcFn(p, sourceAddress, sourcePort);
        m_chordTracker.erase(callback_pair);

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
    m_successor->closest_preceeding(m_info);
    m_stabilizeTimer.Schedule(m_stabilizeFreq);
}

void PennChord::LeaveInitiate() {
    //CHORD_LOG("Leaving Ring");
    m_stabilizeTimer.Cancel();
    m_predecessor->Leave_Suc(m_info, m_successor->m_info);
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

void PennChord::inc_hops() {
    num_hops++;
}

void PennChord::inc_lookups() {
    num_lookups++;
}

void PennChord::HandleRequestTimeout(uint32_t transactionId) {
    // Find transaction
    Ptr<PennChordTransaction> chordTransaction = m_chordTracker [transactionId];
    if (!chordTransaction) {
        // Transaction does not exist
        return;
    }
    // Retransmit and reschedule if needed
    if (chordTransaction->m_retries > chordTransaction->m_maxRetries) {
        // Report failure
        if (chordTransaction->m_chordPacket.m_messageType == PennChordMessage::PennChordPacket::REQ_LOOK) {
            CHORD_LOG("Lookup failed!");
            m_chordTracker.erase(transactionId);
        }
        return;
    } else {
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
      /*if (i > 0 && (i%2 == 0)) {
        s << ".";
        }*/
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
