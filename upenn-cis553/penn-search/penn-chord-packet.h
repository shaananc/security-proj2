/* 
 * File:   PennChordPacket.h
 * Author: user
 *
 * Created on March 20, 2013, 3:06 PM
 */

#ifndef PENNCHORDPACKET_H
#define	PENNCHORDPACKET_H

#include <stdint.h>
#include <vector>
#include "ns3/ipv4-address.h"

#include "ns3/header.h"

#include "ns3/nstime.h"


using namespace ns3;

class PennChordPacket {
public:
    PennChordPacket();
    PennChordPacket(const PennChordPacket& orig);
    virtual ~PennChordPacket();

    // TODO: Define messages for the following functions
    //    PennChord::NodeInfo getLocation();
    //    PennChord::NodeInfo find_successor();
    //    PennChord::NodeInfo closest_preceeding();
    //    bool notify();

    enum TYPE {
    };


private:

public:
    virtual void Print(std::ostream &os) const;
    virtual uint32_t GetSerializedSize(void) const;
    virtual void Serialize(Buffer::Iterator start)const;
    virtual uint32_t Deserialize(Buffer::Iterator start);


};

#endif	/* PENNCHORDPACKET_H */

