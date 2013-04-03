#include "penn-chord.h"

#include "ns3/random-variable.h"
#include "ns3/inet-socket-address.h"
#include "NodeInfo.h"
#include "remote_node.h"

#include <openssl/sha.h>

using namespace ns3;

class remote_node;

/*************************************************************
 *             Functions to Process Penn Chord Messages
 * 
 *************************************************************/

void PennChord::procREQ_SUC(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    //DEBUG_LOG("REQ SUCCESSOR from " << p.originator.address);
    if (m_predecessor.m_info.address.IsEqual(Ipv4Address("0.0.0.0")) ||
            RangeCompare(m_info.location, p.originator.location, m_successor.m_info.location)) {
        remote_node(p.originator, m_socket, m_appPort).reply_successor(m_successor.m_info, p.requestee, p.originator);
    } else {
        m_successor.find_successor(p.originator);
    }
}

void PennChord::procRSP_SUC(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    //DEBUG_LOG("RSP SUCCESSOR from " << p.originator.address);
    //CHORD_LOG("Setting Successor to " << p.m_result.address);
    m_successor.m_info = p.m_result;
    m_successor.notify(m_info);
}

void PennChord::procREQ_CP(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
  //  DEBUG_LOG("REQ PREDECESSOR from " << p.originator.address);
    remote_node(p.originator, m_socket, m_appPort).reply_preceeding(p.originator, m_predecessor.m_info);
}

void PennChord::procRSP_CP(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    //DEBUG_LOG("RSP PREDECESSOR from " << p.originator.address);
    if (!p.m_result.address.IsEqual(Ipv4Address("0.0.0.0")) &&
            RangeCompare(m_info.location, p.m_result.location, m_successor.m_info.location)) {
        m_successor.m_info = p.m_result;
      //  CHORD_LOG("Setting Successor to " << p.m_result.address);
      //  CHORD_LOG("My pred is " << m_predecessor.m_info.address << " and my suc is " << m_successor.m_info.address);
        m_successor.notify(m_info);

    }
}

void PennChord::procLEAVE_SUC(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    //CHORD_LOG("LEAVE SUC from " << p.originator.address);
    m_successor.m_info = p.m_result;
    //CHORD_LOG("Setting Successor to " << p.m_result.address);
    m_successor.Leave_Pred(p.originator, m_info);
}

void PennChord::procLEAVE_PRED(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    //CHORD_LOG("LEAVE PRED from " << p.requestee << " on behalf of " << p.originator.address);
    m_predecessor.m_info = p.m_result;
    //CHORD_LOG("Updating Predecessor to " << p.m_result.address);
    remote_node leaver(p.originator, m_socket, m_appPort);
    leaver.Leave_Conf(p.originator);
}

void PennChord::procRING_DBG(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
   // DEBUG_LOG("RING DEBUG from " << p.originator.address);
    if (p.originator.address != m_info.address && m_successor.m_info.address != m_info.address) {
        PrintInfo();
        m_successor.RingDebug(p.originator);
    }
}

void PennChord::procREQ_NOT(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    //DEBUG_LOG("REQ NOTIFY from " << p.originator.address);

    int res = RangeCompare(m_predecessor.m_info.location, p.originator.location, m_info.location);
    if (m_predecessor.m_info.address.IsEqual(Ipv4Address("0.0.0.0")) ||
            (0 <= res && res < 2)) {
        m_predecessor.m_info = p.originator;
        m_predecessor.last_seen = Now();
        //CHORD_LOG("Updated Predecessor to " << m_predecessor.m_info.address);
    }
}

void PennChord::procREQ_LOOK(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    CHORD_LOG("LOOK from " << p.requestee << " on behalf of " << p.originator.address);
    if (RangeCompare(m_predecessor.m_info.location, p.m_result.location, m_info.location)) {
        // Current node correct lookup
        remote_node req(p.originator, m_socket, m_appPort);
        NodeInfo result = p.m_result;
        result.address = m_info.address;
        // CHORD_LOG("LookupResult " << m_info.location << ", " << result.location << ", " << p.originator.address);        
        // p_result.address will hold the address of the node storing the key
        // p_result.location will hold the key requested
        req.reply_look(p.originator, result);
    } else {
        //  CHORD_LOG("LookupRequest " << m_info.location << ": NextHop " << m_successor.address << ", " << m_successor.location << 
        //        ", " << p.m_result.location); 
        m_successor.find_look(p.originator, p.m_result);
    }
}

void PennChord::procRSP_LOOK(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    CHORD_LOG("RSP_LOOK from " << p.requestee << " on behalf of " << p.originator.address);
}

void PennChord::procLEAVE_CONF(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    CHORD_LOG("LEAVE CONF from " << p.requestee << " on behalf of " << p.originator.address);
    LeaveOverlay();
}

