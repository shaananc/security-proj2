/* 
 * File:   PennChordMessage::PennChordPacket.cc
 * Author: user
 * 
 * Created on March 20, 2013, 3:06 PM
 */

#include "penn-chord-message.h"

#include "ns3/header.h"
#include "ns3/ipv4-address.h"
#include "ns3/packet.h"
#include "ns3/object.h"
#include "NodeInfo.h"


using namespace ns3;



// TODO Implement All

void PennChordMessage::PennChordPacket::Print(std::ostream &os)const {
}

uint32_t PennChordMessage::PennChordPacket::GetSerializedSize(void)const {
    return 24;
}

void PennChordMessage::PennChordPacket::Serialize(Buffer::Iterator start)const {
    Buffer::Iterator i = start;
    i.WriteHtonU16(this->m_messageType);
    i.WriteHtonU32(m_transactionId);
    
    if(m_messageType != RSP_INF && m_messageType != RSP_BOOL){
        i.WriteU64(0);
    } else {
        i.WriteHtonU32(m_result.location);
        i.WriteU32(m_result.address.Get());
    }
    
    i.WriteHtonU32(originator.Get());
    i.WriteHtonU32(requestee.Get());
}

uint32_t PennChordMessage::PennChordPacket::Deserialize(Buffer::Iterator start) {
    Buffer::Iterator i = start;
    m_messageType = (Chord_Type)i.ReadNtohU16();
    m_transactionId = i.ReadNtohU32();
    m_result.location = i.ReadNtohU32();
    m_result.address = Ipv4Address(i.ReadNtohU32());
    
    originator = Ipv4Address(i.ReadNtohU32());
    requestee = Ipv4Address(i.ReadNtohU32());
    
    return this->GetSerializedSize();
}
