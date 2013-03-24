/* 
 * File:   remote_node.cc
 * Author: user
 * 
 * Created on March 20, 2013, 2:21 PM
 */

#include "remote_node.h"
#include "penn-chord-message.h"

#include "ns3/penn-chord.h"
#include "ns3/inet-socket-address.h"
#include "NodeInfo.h"

using namespace ns3;


// TODO: remove code duplication

remote_node::remote_node() {
}

remote_node::remote_node(const remote_node& orig) {
}

remote_node::~remote_node() {
}

remote_node::remote_node(NodeInfo info,
        Ptr<Socket> m_socket,
        uint16_t m_appPort) {

    m_info = info;
    this->m_socket = m_socket;
    this->m_appPort = m_appPort;
    srand(time(NULL));
    m_currentTransactionId = rand() % ~0;
    NodeInfo s;
    s.address = Ipv4Address("0.0.0.0");
    this->m_sucessor = s;
    NodeInfo t;
    t.address = Ipv4Address("0.0.0.0");
    m_predecessor = t;


}

uint32_t remote_node::GetNextTransactionId() {
    if (m_currentTransactionId == ~0) {
        m_currentTransactionId = 0;
    } else {
        m_currentTransactionId++;
    }
    return m_currentTransactionId;
}

void remote_node::SendRPC(PennChordMessage::PennChordPacket p) {
    uint32_t transactionId = GetNextTransactionId();
    Ptr<Packet> packet = Create<Packet> ();
    PennChordMessage message = PennChordMessage(PennChordMessage::CHOR_PAC, transactionId);
    p.m_transactionId = GetNextTransactionId();
    message.SetChordPacket(p);
    packet->AddHeader(message);
    m_socket->SendTo(packet, 0, InetSocketAddress(m_info.address, m_appPort));
//    p.Print(std::cout);
//    std::cout << "That is being sent to " << m_info.address << std::endl;
}

void remote_node::getLocation(NodeInfo originator) {

    PennChordMessage::PennChordPacket p;
    // Change packet variables
    p.m_messageType = PennChordMessage::PennChordPacket::REQ_LOC;
    p.requestee = m_info.address;
    p.originator = originator;
    SendRPC(p);

}

void remote_node::join() {
    PennChordMessage::PennChordPacket p;
    // Change packet variables
    p.m_messageType = PennChordMessage::PennChordPacket::REQ_LOC;
    SendRPC(p);

}

void remote_node::find_successor(NodeInfo originator) {

    PennChordMessage::PennChordPacket p;
    // Change packet variables
    p.m_messageType = PennChordMessage::PennChordPacket::REQ_SUC;
    p.requestee = m_info.address;
    p.originator = originator;
    SendRPC(p);

}
//blah

void remote_node::reply_successor(NodeInfo successor, Ipv4Address requestee, NodeInfo originator) {
    PennChordMessage::PennChordPacket p;
    // Change packet variables
    p.m_messageType = PennChordMessage::PennChordPacket::RSP_SUC;
    p.m_result = successor;
    p.requestee = requestee;
    p.originator = originator;
    SendRPC(p);

}

void remote_node::notify(NodeInfo originator) {

    PennChordMessage::PennChordPacket p;
    // Change packet variables
    p.m_messageType = PennChordMessage::PennChordPacket::REQ_NOT;
    p.requestee = m_info.address;
    p.originator = originator;
    SendRPC(p);

}

void remote_node::closest_preceeding(NodeInfo originator) {

    //std::cout << "SENDING STAB to " << originator.address << std::endl;
    PennChordMessage::PennChordPacket p;
    // Change packet variables
    p.m_messageType = PennChordMessage::PennChordPacket::REQ_CP;
    p.requestee = m_info.address;
    p.originator = originator;
    SendRPC(p);
}

void remote_node::reply_preceeding(NodeInfo originator, NodeInfo predecessor) {
    PennChordMessage::PennChordPacket p;
    // Change packet variables
    p.m_messageType = PennChordMessage::PennChordPacket::RSP_CP;
    p.m_result = predecessor;
    //cout << "SENDING BACK " << predecessor.address << endl;
    p.requestee = m_info.address;
    p.originator = originator;
    SendRPC(p);
}

void remote_node::processPacket(PennChordMessage::PennChordPacket p) {
    //Make appropriate callbacks
    // switch on p.type
    // remove from pending transactions
}


void remote_node::RingDebug(NodeInfo originator){
    PennChordMessage::PennChordPacket p;
    // Change packet variables
    p.m_messageType = PennChordMessage::PennChordPacket::RING_DBG;
    p.originator = originator;
    SendRPC(p);
}
