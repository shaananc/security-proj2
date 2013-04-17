
#include "penn-chord.h"

#include "ns3/random-variable.h"
#include "ns3/inet-socket-address.h"
#include "NodeInfo.h"
#include "remote_node.h"

#include <openssl/sha.h>

using namespace ns3;
extern bool inLookup;
class remote_node;

/*************************************************************
 *             Functions to Process Penn Chord Messages
 * 
 *************************************************************/

void PennChord::procREQ_PRE(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    CHORD_LOG("REQ PREDECESSOR from " << ReverseLookup(p.originator.address));
    if (/*m_predecessor->m_info.address.IsEqual(Ipv4Address("0.0.0.0")) ||*/
            RangeCompare(m_info.location, p.originator.location, m_successor->m_info.location)) {

        remote_node(p.originator, m_socket, m_appPort).reply_predecessor(m_info, p.requestee, p.originator, p.m_transactionId);
    } else {
        m_successor->find_predecessor(p.originator, p.lookupLocation, p.m_transactionId);
    }
}

void PennChord::procRSP_PRE(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    //DEBUG_LOG("RSP SUCCESSOR from " << p.originator.address);
    //CHORD_LOG("RSP_SUCCESSOR: Setting Successor to " << ReverseLookup(p.m_result.address));
    if (RangeCompare(m_info.location, p.m_result.location, m_successor->m_info.location) == 1) {
        m_successor->m_info = p.m_result;
    }
    //m_successor->notify(m_info);
    //m_chordTracker.erase(p.m_transactionId);
}

void PennChord::procREQ_SUC(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    //CHORD_LOG("REQ SUCCESSOR from " << ReverseLookup(p.originator.address));
    if (/*m_predecessor.m_info.address.IsEqual(Ipv4Address("0.0.0.0")) ||*/
            RangeCompare(m_info.location, p.lookupLocation, m_successor->m_info.location)) {

        CHORD_LOG("Successor Found");
        p.m_resolved = true;
        remote_node(p.originator, m_socket, m_appPort).reply_successor(m_successor->m_info, p.requestee, p.originator, p.m_transactionId);
    } else {
      
      //      if(inLookup) num_hops++; //Need to separate out this from normal traffic
        CHORD_LOG("No successor. Forwarding");
        p.m_resolved = false;
        // TODO: do find_predecessor after consulting finger table instead
        m_successor->find_successor(p.originator, p.lookupLocation, p.m_transactionId);
    }
}

void PennChord::procREQ_LOOKUP(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    //CHORD_LOG("REQ SUCCESSOR from " << ReverseLookup(p.originator.address));
    if (/*m_predecessor.m_info.address.IsEqual(Ipv4Address("0.0.0.0")) ||*/
            RangeCompare(m_info.location, p.lookupLocation, m_successor->m_info.location)) {

      CHORD_LOG("LookupResult<" << strHash(m_info.location) << "," << strHash(p.lookupLocation) << "," << p.originator.address << ">");
        p.m_resolved = true;
        remote_node(p.originator, m_socket, m_appPort).reply_successor(m_successor->m_info, p.requestee, p.originator, p.m_transactionId);
    } else {
      CHORD_LOG("LookupRequest< " << strHash(m_info.location) << ">: NextHop< " << m_successor->m_info.address << ", " << strHash(m_successor->m_info.location) << ", " << strHash(p.lookupLocation) << ">");  //p_m_result isn't right
        num_hops++; 
	//CHORD_LOG("LookupRequestion<");
        p.m_resolved = false;
        // TODO: do find_predecessor after consulting finger table instead
        m_successor->find_lookup(p.originator, p.lookupLocation, p.m_transactionId);
    }
}


void PennChord::procRSP_SUC(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    //DEBUG_LOG("RSP SUCCESSOR from " << p.originator.address);
    //CHORD_LOG("RSP_SUCCESSOR: Setting Successor to " << ReverseLookup(p.m_result.address));

    m_successor->m_info = p.m_result;
    m_successor->notify(m_info);

}

void PennChord::procREQ_CP(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    //CHORD_LOG("REQ PREDECESSOR from " << ReverseLookup(p.originator.address));
    remote_node(p.originator, m_socket, m_appPort).reply_preceeding(p.originator, m_predecessor->m_info);
}

void PennChord::procRSP_CP(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    //CHORD_LOG("RSP PREDECESSOR from " << ReverseLookup(p.originator.address) << " WHICH IS " << ReverseLookup(p.m_result.address));
    //    DEBUG_LOG("RC on RSP CP from " << sourceAddress);

    bool range = RangeCompare(m_info.location, p.m_result.location, m_successor->m_info.location);
    if (!p.m_result.address.IsEqual(Ipv4Address("0.0.0.0")) && (range == 1)
            && p.m_result.address != m_info.address
            ) {
        m_successor->m_info = p.m_result;
        //CHORD_LOG("Setting Successor to " << ReverseLookup(p.m_result.address));
        //CHORD_LOG("My pred is " << m_predecessor->m_info.address << " and my suc is " << m_successor->m_info.address);
        m_successor->notify(m_info);

    } else if (!p.m_result.address.IsEqual(Ipv4Address("0.0.0.0")) && (range == 0)
            && p.m_result.address != m_info.address) {
        m_successor->notify(m_info);
    }
}

void PennChord::procLEAVE_SUC(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    //CHORD_LOG("LEAVE SUC from " << p.originator.address);
    m_successor->m_info = p.m_result;
    //CHORD_LOG("Setting Successor to " << p.m_result.address);
    m_successor->Leave_Pred(p.originator, m_info);
}

void PennChord::procLEAVE_PRED(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    //CHORD_LOG("LEAVE PRED from " << p.requestee << " on behalf of " << p.originator.address);
    m_predecessor->m_info = p.m_result;
    m_predecessor->last_seen = Now();
    CHORD_LOG("Updating Predecessor to " << p.m_result.address);
    remote_node leaver(p.originator, m_socket, m_appPort);
    leaver.Leave_Conf(p.originator);
}

void PennChord::procRING_DBG(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    // DEBUG_LOG("RING DEBUG from " << p.originator.address);
    //CHORD_LOG("RECV DEBUG: " << ReverseLookup(p.originator.address) << " Suc: " << ReverseLookup(m_successor.m_info.address) );
    if (p.originator.address != m_info.address && m_successor->m_info.address != m_info.address) {
        PrintInfo();

        m_successor->RingDebug(p.originator, p.m_result.address.Get() + 1);
    } else {
        CHORD_LOG(p.m_result.address.Get() << " is the total number of nodes in the ring\n");
    }
}

void PennChord::procREQ_NOT(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    //DEBUG_LOG("RC on REQ NOTIFY from " << p.originator.address);

    int res = RangeCompare(m_predecessor->m_info.location, p.originator.location, m_info.location);
    if (m_predecessor->m_info.address.IsEqual(Ipv4Address("0.0.0.0")) ||
            (0 < res && res < 2)) {
        m_predecessor->m_info = p.originator;
        m_predecessor->last_seen = Now();

        if (joined == 1) {
            joined++;
            m_joinedCallback();
        }

        //CHORD_LOG("Updated Predecessor to " << ReverseLookup(m_predecessor.m_info.address));
        }
    }

void PennChord::procREQ_LOOK(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
  //     CHORD_LOG("LOOK from " << p.requestee << " on behalf of " << p.originator.address);
  // num_lookups++; 
    if (RangeCompare(m_predecessor->m_info.location, p.m_result.location, m_info.location)) {
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
        m_successor->find_look(p.originator, p.m_result);
    }
}

void PennChord::procRSP_LOOK(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    // TODO: process depending on RSP_PRE or RSP_SUC
    // start a new transaction in case of RSP_PRE
    //CHORD_LOG("RSP_LOOK from " << p.requestee << " on behalf of " << p.originator.address);
    if (!m_lookupSuccessFn.IsNull()) {
        m_lookupSuccessFn(p.m_result.location, SHA_DIGEST_LENGTH, p.m_result.address, p.m_transactionId);
    }
    //m_chordTracker.erase(p.m_transactionId);
}

void PennChord::procLEAVE_CONF(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
    //CHORD_LOG("LEAVE CONF from " << p.requestee << " on behalf of " << p.originator.address);
    LeaveOverlay();
}

void PennChord::procREQ_FINGER(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
}

void PennChord::procRSP_FINGER(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort) {
}

