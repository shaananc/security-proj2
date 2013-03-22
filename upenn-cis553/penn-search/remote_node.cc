/* 
 * File:   remote_node.cc
 * Author: user
 * 
 * Created on March 20, 2013, 2:21 PM
 */

#include "remote_node.h"
#include "penn-chord-message.h"

#include "ns3/inet-socket-address.h"

using namespace ns3;

remote_node::remote_node() {
}

remote_node::remote_node(const remote_node& orig) {
}

remote_node::~remote_node() {
}

remote_node::remote_node(PennChord::NodeInfo info, Ptr<Socket> m_socket, uint16_t m_appPort) {
    m_info = info;
    this->m_socket = m_socket;
    this->m_appPort = m_appPort;;
    srand (time(NULL));
    m_currentTransactionId = rand() % ~0;
    
}

uint32_t remote_node::GetNextTransactionId(){
    if(m_currentTransactionId == ~0){
        m_currentTransactionId = 0;
    }
    else{m_currentTransactionId++;}
    return m_currentTransactionId;
}




PennChord::NodeInfo remote_node::getLocation() {
    uint32_t transactionId = GetNextTransactionId();
    Ptr<Packet> packet = Create<Packet> ();
    PennChordMessage message = PennChordMessage(PennChordMessage::CHOR_PAC, transactionId);
    PennChordMessage::PennChordPacket p;
    
    packet->AddHeader(message);
    m_socket->SendTo(packet, 0, InetSocketAddress(m_info.address, m_appPort));

}

PennChord::NodeInfo remote_node::find_successor() {

}

bool notify() {

}

PennChord::NodeInfo closest_preceeding() {

}
