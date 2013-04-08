/* 
 * File:   remote_node.h
 * Author: user
 *
 * Created on March 20, 2013, 2:21 PM
 */

#ifndef REMOTE_NODE_H
#define	REMOTE_NODE_H

#include <vector>
#include <map>
#include <algorithm>
#include "ns3/inet-socket-address.h"
#include "ns3/socket.h"
#include "penn-chord-message.h"
#include "ns3/NodeInfo.h"
#include "ns3/nstime.h"

using namespace std;
using namespace ns3;

class remote_node {
public:
    remote_node();

    remote_node(NodeInfo info, Ptr<Socket> m_socket, uint16_t m_appPort);

    remote_node(const remote_node& orig);
    virtual ~remote_node();

    void getLocation(NodeInfo originator);
    void reply_location(NodeInfo location);

    void join();
    void find_successor(NodeInfo originator, unsigned char location[], uint32_t transactionId_original);
    void reply_successor(NodeInfo successor, Ipv4Address requestee, NodeInfo originator, uint32_t transactionId_original);
    
    void find_predecessor(NodeInfo originator, unsigned char location[], uint32_t transactionId_original);
    void reply_predecessor(NodeInfo predecessor, Ipv4Address requestee, NodeInfo originator, uint32_t transactionId_original);

    void closest_preceeding(NodeInfo originator);
    void reply_preceeding(NodeInfo originator, NodeInfo predecessor);

    void SendRPC(PennChordMessage::PennChordPacket p);
    void notify(NodeInfo originator);
    void processPacket(PennChordMessage::PennChordPacket p);
    
    void RingDebug(NodeInfo originator, uint32_t n);

    void Leave_Suc(NodeInfo originator, NodeInfo successor);
    void Leave_Pred(NodeInfo originator, NodeInfo predecessor);
    void Leave_Conf(NodeInfo originator);

    void find_look(NodeInfo originator, NodeInfo requested);
    void reply_look(NodeInfo originator, NodeInfo result);

    uint32_t GetNextTransactionId();

    void update_node(NodeInfo node, std::map<std::string, std::vector<string> > &docs);


    NodeInfo m_info;
    // This represents the latest up to date info
    NodeInfo m_successor;
    NodeInfo m_predecessor;
    
    Time last_seen;
    
    Ptr<Socket> m_socket;
    uint16_t m_appPort;
    uint32_t m_currentTransactionId;

    //Maintains (key, document) list the node is responsible for
    std::map<std::string, vector<std::string> > documents;

    //Maintains the list of (key, document) lists that have to be publsihed
    std::map<std::string, vector<std::string> > need_to_publish;

private:

};

#endif	/* REMOTE_NODE_H */

