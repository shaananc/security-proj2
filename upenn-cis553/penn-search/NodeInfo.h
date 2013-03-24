/* 
 * File:   NodeInfo.h
 * Author: user
 *
 * Created on March 22, 2013, 3:23 AM
 */

#ifndef NODEINFO_H
#define	NODEINFO_H

#include <string>
#include <openssl/sha.h>

using namespace ns3;

typedef struct NodeInfo {
    u_char location[SHA_DIGEST_LENGTH];
    Ipv4Address address;
} NodeInfo;



#endif	/* NODEINFO_H */

