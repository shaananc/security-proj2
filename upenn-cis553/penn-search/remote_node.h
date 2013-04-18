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

class remote_node : public SimpleRefCount<remote_node>  {
public:
    remote_node();

    remote_node(NodeInfo info, Ptr<Socket> m_socket, uint16_t m_appPort);

    remote_node(const remote_node& orig);
    virtual ~remote_node();

    PennChordMessage::PennChordPacket getLocation(NodeInfo originator);
    PennChordMessage::PennChordPacket reply_location(NodeInfo location);

    PennChordMessage::PennChordPacket join();
    PennChordMessage::PennChordPacket find_successor(NodeInfo originator, unsigned char location[], uint32_t transactionId_original);
    PennChordMessage::PennChordPacket find_lookup(NodeInfo originator, unsigned char location[], uint32_t transactionId_original);
    PennChordMessage::PennChordPacket find_finger(NodeInfo originator, unsigned char location[], uint32_t transactionId_original, uint8_t fingerNum);
    PennChordMessage::PennChordPacket reply_finger(NodeInfo finger, Ipv4Address requestee, NodeInfo originator, uint32_t transactionId_original, uint8_t fingerNum);
    PennChordMessage::PennChordPacket reply_successor(NodeInfo successor, Ipv4Address requestee, NodeInfo originator, uint32_t transactionId_original);
    
    PennChordMessage::PennChordPacket find_predecessor(NodeInfo originator, unsigned char location[], uint32_t transactionId_original);
    PennChordMessage::PennChordPacket reply_predecessor(NodeInfo predecessor, Ipv4Address requestee, NodeInfo originator, uint32_t transactionId_original);

    PennChordMessage::PennChordPacket closest_preceeding(NodeInfo originator);
    PennChordMessage::PennChordPacket reply_preceeding(NodeInfo originator, NodeInfo predecessor);

    void SendRPC(PennChordMessage::PennChordPacket p);
    PennChordMessage::PennChordPacket notify(NodeInfo originator);
    void processPacket(PennChordMessage::PennChordPacket p);
    
    PennChordMessage::PennChordPacket RingDebug(NodeInfo originator, uint32_t n, uint32_t transactionId_original);

    PennChordMessage::PennChordPacket Leave_Suc(NodeInfo originator, NodeInfo successor);
    PennChordMessage::PennChordPacket Leave_Pred(NodeInfo originator, NodeInfo predecessor);
    PennChordMessage::PennChordPacket Leave_Conf(NodeInfo originator);

    PennChordMessage::PennChordPacket find_look(NodeInfo originator, NodeInfo requested);
    PennChordMessage::PennChordPacket reply_look(NodeInfo originator, NodeInfo result);

    uint32_t GetNextTransactionId();

    //void update_node(NodeInfo node, std::map<std::string, std::vector<string> > &docs);

    //void update_publish_list(NodeInfo node, std::map<std::string, std::vector<string> > &keyDocs); 

    //void remove_publish_list(NodeInfo node, std::vector<std::string> &keys);

    NodeInfo m_info;
    // This represents the latest up to date info
    NodeInfo m_successor;
    NodeInfo m_predecessor;
    
    Time last_seen;
    
    Ptr<Socket> m_socket;
    uint16_t m_appPort;
    uint32_t m_currentTransactionId;

    //Maintains (key, document) list the node is responsible for
    //std::map<std::string, vector<std::string> > documents;

    //Maintains the list of (key, document) lists that have to be publsihed
    //std::map<std::string, vector<std::string> > need_to_publish;


private:

};

#endif	/* REMOTE_NODE_H */

