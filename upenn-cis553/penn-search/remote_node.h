/* 
 * File:   remote_node.h
 * Author: user
 *
 * Created on March 20, 2013, 2:21 PM
 */

#ifndef REMOTE_NODE_H
#define	REMOTE_NODE_H

#include <vector>
#include "ns3/inet-socket-address.h"
#include "ns3/socket.h"
#include "penn-chord-message.h"
#include "ns3/NodeInfo.h"

using namespace std;
using namespace ns3;



class remote_node {
public:
    remote_node();
    
    remote_node(NodeInfo info, Ptr<Socket> m_socket, uint16_t m_appPort, Ipv4Address m_originator);

    remote_node(const remote_node& orig);
    virtual ~remote_node();

    void getLocation();
    void reply_location(NodeInfo location);
    
    void join();
    void find_successor();
    void reply_successor(NodeInfo successor, Ipv4Address requestee, Ipv4Address originator);
    
    void closest_preceeding();
    void reply_preceeding(NodeInfo preceeding);
    
    void SendRPC(PennChordMessage::PennChordPacket p);
    void notify();
    void processPacket(PennChordMessage::PennChordPacket p);


    uint32_t GetNextTransactionId();


    NodeInfo m_info;
    // This represents the latest up to date info
    NodeInfo m_sucessor;
    NodeInfo m_predecessor;

    Ptr<Socket> m_socket;
    uint16_t m_appPort;
    uint32_t m_currentTransactionId;
    Ipv4Address originator;


private:
    
};

#endif	/* REMOTE_NODE_H */

