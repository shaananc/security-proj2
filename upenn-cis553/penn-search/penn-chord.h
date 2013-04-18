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

#ifndef PENN_CHORD_H
#define PENN_CHORD_H

#include "ns3/penn-application.h"
#include "ns3/penn-chord-message.h"
#include "ns3/penn-chord-transaction.h"
#include "ns3/ping-request.h"

#include "ns3/ipv4-address.h"
#include <map>
#include <set>
#include <vector>
#include <string>
#include "ns3/socket.h"
#include "ns3/nstime.h"
#include "ns3/timer.h"
#include "ns3/uinteger.h"
#include "ns3/boolean.h"

#include "ns3/NodeInfo.h"
#include "remote_node.h"

using namespace ns3;

extern uint32_t num_hops;
extern uint32_t num_lookups;
string strHash(unsigned char *hash);
bool RangeCompare(unsigned char *low, unsigned char *mid, unsigned char *high);
void PrintHash(unsigned char *hash, std::ostream &os);

class PennChord : public PennApplication {
public:
    static TypeId GetTypeId(void);
    PennChord();
    virtual ~PennChord();

    void SendPing(Ipv4Address destAddress, std::string pingMessage);
    void RecvMessage(Ptr<Socket> socket);
    void ProcessPingReq(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
    void ProcessPingRsp(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
    void AuditPings();
    uint32_t GetNextTransactionId();
    void StopChord();

    // Callback with Application Layer (add more when required)
    void SetPingSuccessCallback(Callback <void, Ipv4Address, std::string> pingSuccessFn);
    void SetPingFailureCallback(Callback <void, Ipv4Address, std::string> pingFailureFn);
    void SetPingRecvCallback(Callback <void, Ipv4Address, std::string> pingRecvFn);

    // From PennApplication
    virtual void ProcessCommand(std::vector<std::string> tokens);


    void ProcessChordMessage(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
    void procREQ_SUC(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort);
    void procREQ_LOOKUP(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort);
    void procRSP_SUC(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort);
    void procREQ_PRE(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort);
    void procRSP_PRE(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort);
    void procREQ_CP(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort);
    void procRSP_CP(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort);
    void procRING_DBG(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort);
    void procREQ_NOT(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort);
    void procREQ_LOOK(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort);
    void procLEAVE_SUC(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort);
    void procLEAVE_PRED(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort);
    void procLEAVE_CONF(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort);
    void procRSP_LOOK(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort);
    void procREQ_FINGER(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort);
    void procRSP_FINGER(PennChordMessage::PennChordPacket p, Ipv4Address sourceAddress, uint16_t sourcePort);

    NodeInfo getSuccessor();
    NodeInfo getPredecessor();
    
    void JoinOverlay(Ipv4Address landmark);
    void LeaveInitiate();
    void LeaveOverlay();
    void CreateOverlay();
    uint32_t Lookup(unsigned char location[]);
    void SetLookupSuccessCallback(Callback<void, uint8_t*, uint8_t, Ipv4Address, uint32_t> lookupSuccessFn);
    void SetLookupFailureCallback(Callback<void, uint8_t*, uint8_t, uint32_t> lookupFailureFn);
    void SetJoinCallback(Callback<void> cb);

    void PrintInfo();

    void stabilize();
    bool notify(int32_t address);



    void HandleRequestTimeout(uint32_t transactionId);

    void FixFingers();
    void AuditFingers();
    Ptr<remote_node> FindFinger(uint8_t location[]);

protected:
    virtual void DoDispose();

private:
    virtual void StartApplication(void);
    virtual void StopApplication(void);

    void PopulateFingerLocationList();
    void AddPowerOfTwo (unsigned char location[], uint16_t powerOfTwo);

    uint32_t m_currentTransactionId;
    Ptr<Socket> m_socket;
    Time m_pingTimeout;
    Time m_stabilizeFreq;
    Time m_requestTimeout;
    Time m_fixFingerInterval;
    Time m_auditFingerInterval;
    Time m_debugTimeout;
    Time m_leaveTimeout;


    uint16_t m_appPort;
    uint8_t m_maxRequestRetries;
    // Timers
    Timer m_auditPingsTimer;
    Timer m_stabilizeTimer;
    Timer m_fixFingerTimer;
    Timer m_auditFingerTimer;
    // Ping tracker
    std::map<uint32_t, Ptr<PingRequest> > m_pingTracker;
    // Callbacks
    Callback <void, Ipv4Address, std::string> m_pingSuccessFn;
    Callback <void, Ipv4Address, std::string> m_pingFailureFn;
    Callback <void, Ipv4Address, std::string> m_pingRecvFn;
    Callback <void, uint8_t*, uint8_t, Ipv4Address, uint32_t> m_lookupSuccessFn;
    Callback <void, uint8_t*, uint8_t, uint32_t> m_lookupFailureFn;
    Callback<void> m_joinedCallback;

    int joined;
    NodeInfo m_info;
    // node: self 
    Ptr<remote_node> m_remoteNodeSelf;
    // node: successor
    Ptr<remote_node> m_successor;
    // node: predecessor
    Ptr<remote_node> m_predecessor;
    std::map<uint32_t, Ptr<PennChordTransaction> > m_chordTracker;
    Ptr<remote_node> m_landmark;
    std::map<uint8_t, uint8_t*> m_fingerLocationList;
    std::map<uint8_t, Ptr<remote_node> > m_fingerTable;
    std::map<uint8_t, bool> m_fingerReceipt;
};

#endif


