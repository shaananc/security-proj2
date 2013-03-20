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
    
    remote_node(PennChord::NodeInfo info);
    
    remote_node(const remote_node& orig);
    virtual ~remote_node();

    PennChord::NodeInfo getLocation();
    PennChord::NodeInfo find_successor();
    PennChord::NodeInfo closest_preceeding();
    bool notify();
    
    PennChord::NodeInfo m_info;

private:

};

#endif	/* REMOTE_NODE_H */

