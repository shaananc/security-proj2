/* 
 * File:   PennChordMessage::PennChordPacket.cc
 * Author: user
 * 
 * Created on March 20, 2013, 3:06 PM
 */

#include "penn-chord-message.h"
#include "penn-chord.h"

#include "ns3/header.h"
#include "ns3/ipv4-address.h"
#include "ns3/packet.h"
#include "ns3/object.h"
#include "NodeInfo.h"


#include <openssl/sha.h>


using namespace ns3;



// TODO Implement All

void PennChordMessage::PennChordPacket::Print(std::ostream &os)const {
    switch (m_messageType) {
        case(REQ_CP):
            os << "REQ PREDECESSOR";
            break;
        case(REQ_NOT):
            os << "REQ NOTIFY";
            break;
        case(REQ_SUC):
            os << "REQ SUCCESSOR";
            break;
        case(RSP_CP):
            os << "RSP PREDECESSOR";
            break;
        case(RSP_SUC):
            os << "RSP SUCCESSOR";
            break;
        case(RING_DBG):
            os << "RING DEUBG";
            break;
        case(LEAVE_SUC):
            os << "LEAVE SUCCSSOR";
            break;
        case(LEAVE_PRED):
            os << "LEAVE PREDECESSOR";
            break;
        case(LEAVE_CONF):
            os << "LEAVE CONFIRMED";
            break;
        case(REQ_LOOK):
            os << "REQ LOOK";
            break;
        case(RSP_LOOK):
            os << "RSP LOOK";
            break;
            
        default:
            os << "INVALID MESSAGE TYPE: " << m_messageType;
            break;
    }

    os << std::endl;
    os << "Result Address " << m_result.address << std::endl;
    os << "Result Location ";
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        os << std::hex << (int) m_result.location[i];
    }

    os << std::endl << std::dec;
    os << originator.address << " originator and " << requestee << " requestee" << std::endl;
    os << "Originator Location ";
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        os << std::hex << (int) originator.location[i];
    }
    os << std::endl;

    os << std::dec << m_transactionId << " transaction id" << std::endl;
    os << "\n\n\n";
}

uint32_t PennChordMessage::PennChordPacket::GetSerializedSize(void)const {
    return sizeof (uint16_t) + sizeof (uint32_t)*4 + SHA_DIGEST_LENGTH * 3 + 2;
}

void PennChordMessage::PennChordPacket::Serialize(Buffer::Iterator start)const {
    Buffer::Iterator i = start;
    i.WriteHtonU16(this->m_messageType);
    i.WriteHtonU32(m_transactionId);


    for (int j = 0; j < SHA_DIGEST_LENGTH; j++) {
        i.WriteU8(m_result.location[j]);
    }



    i.WriteHtonU32(m_result.address.Get());

    i.WriteHtonU32(originator.address.Get());

    for (int j = 0; j < SHA_DIGEST_LENGTH; j++) {
        i.WriteU8(originator.location[j]);
    }

    i.WriteHtonU32(requestee.Get());

    for (int j = 0; j < SHA_DIGEST_LENGTH; j++) {
        i.WriteU8(lookupLocation[j]);
    }

    i.WriteU8(m_resolved);
    i.WriteU8(m_chordLevelLookup);
}

uint32_t PennChordMessage::PennChordPacket::Deserialize(Buffer::Iterator start) {
    Buffer::Iterator i = start;
    m_messageType = (Chord_Type) i.ReadNtohU16();
    m_transactionId = i.ReadNtohU32();


    for (int j = 0; j < SHA_DIGEST_LENGTH; j++) {
        m_result.location[j] = i.ReadU8();
    }




    m_result.address = Ipv4Address(i.ReadNtohU32());

    originator.address = Ipv4Address(i.ReadNtohU32());

    for (int j = 0; j < SHA_DIGEST_LENGTH; j++) {
        originator.location[j] = i.ReadU8();
    }

    requestee = Ipv4Address(i.ReadNtohU32());

    for (int j = 0; j < SHA_DIGEST_LENGTH; j++) {
        lookupLocation[j] = i.ReadU8();
    }

    m_resolved = i.ReadU8();
    m_chordLevelLookup = i.ReadU8();


    return GetSerializedSize();
}
