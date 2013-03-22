/* 
 * File:   remote_node.h
 * Author: user
 *
 * Created on March 20, 2013, 2:21 PM
 */

#ifndef REMOTE_NODE_H
#define	REMOTE_NODE_H

#include "penn-chord.h"


using namespace ns3;

class remote_node {
public:
    remote_node();

    remote_node(PennChord::NodeInfo info, Ptr<Socket> m_socket, uint16_t m_appPort);

    remote_node(const remote_node& orig);
    virtual ~remote_node();

    PennChord::NodeInfo getLocation();
    PennChord::NodeInfo find_successor();
    PennChord::NodeInfo closest_preceeding();
    bool notify();
    uint32_t GetNextTransactionId();
    
    
    PennChord::NodeInfo m_info;
    Ptr<Socket> m_socket;
    uint16_t m_appPort;
    uint32_t m_currentTransactionId;

private:

};

#endif	/* REMOTE_NODE_H */

