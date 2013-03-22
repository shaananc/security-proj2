/* 
 * File:   remote_node.h
 * Author: user
 *
 * Created on March 20, 2013, 2:21 PM
 */

#ifndef REMOTE_NODE_H
#define	REMOTE_NODE_H

#include "penn-chord.h"
#include <vector>

using namespace std;
using namespace ns3;

class remote_node {
public:
    remote_node();

    remote_node(PennChord::NodeInfo info, Ptr<Socket> m_socket, uint16_t m_appPort);

    remote_node(const remote_node& orig);
    virtual ~remote_node();

    void getLocation();
    void find_successor();
    void closest_preceeding();
    void SendRPC(PennChordMessage::PennChordPacket p);
    void notify();
    void processPacket(PennChordMessage::PennChordPacket p);
    
    
    vector<uint32_t> GetPendingTransactions();
    
    uint32_t GetNextTransactionId();
    
    
    PennChord::NodeInfo m_info;
    Ptr<Socket> m_socket;
    uint16_t m_appPort;
    uint32_t m_currentTransactionId;

    
    
private:
    vector<uint32_t> pendingTransactions;
};

#endif	/* REMOTE_NODE_H */

