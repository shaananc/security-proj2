/* 
 * File:   remote_node.cc
 * Author: user
 * 
 * Created on March 20, 2013, 2:21 PM
 */

#include "remote_node.h"

using namespace ns3;

remote_node::remote_node() {
}

remote_node::remote_node(const remote_node& orig) {
}

remote_node::~remote_node() {
}

remote_node::remote_node(PennChord::NodeInfo info) {
    m_info = info;
}

PennChord::NodeInfo getInfo() {

}

PennChord::NodeInfo find_successor() {

}

bool notify() {

}

PennChord::NodeInfo closest_preceeding() {

}
