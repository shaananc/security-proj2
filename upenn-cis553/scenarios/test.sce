# Turn on traffic traces for LS module on all nodes.
* LS VERBOSE TRAFFIC ON
# Turn on all traces for LS module on node 1
1 LS VERBOSE ALL ON
# Turn on traffic traces for APP module on all nodes.
* APP VERBOSE TRAFFIC ON
# Turn on all traces for APP module on node 1 
1 APP VERBOSE ALL ON

# Advance Time pointer by 15 seconds. Allow the routing protocol to stabilize.
TIME 15000

# Start traffic flow from node 1 to all the nodes.
1 APP TRAFFIC START *

# Advance time by 100 milliseconds.
TIME 100

# Stop Traffic flowing from node 1 to all the nodes
1 APP TRAFFIC STOP *

# Send PING from node 1 to node 8 (its neighbor). Please note that "LS PING" only works between neighbors as it uses UDP broadcast. Also, PING message should not contain blank spaces.
1 LS PING 8 hello1!
# Advance Time by 10 milliseconds.
TIME 10

# Bring down Link Number 6.
LINK DOWN 6
TIME 10
1 LS PING 8 hello2!
TIME 10
# Bring up Link Number 6.
LINK UP 6
1 LS PING 8 hello3!
TIME 10

# Bring down all links of node 1
NODELINKS DOWN 1
1 LS PING 9 hello4!
TIME 10
# Bring up all links of node 1
NODELINKS UP 1
1 LS PING 8 hello5!
TIME 10

# Bring down link(s) between nodes 1 and 8
LINK DOWN 1 8
1 LS PING 8 hello6!
TIME 10
# Bring up link(s) between nodes 1 and 8
LINK UP 1 8
1 LS PING 8 hello7!
TIME 10

# Send application level PING from node 1 to node 8. Note that Application level PINGs are unicast packets and supposed to traverse multiple hops.
1 APP PING 8 appHello1!
TIME 4000

# Dump Link State Routing Table.
1 LS DUMP ROUTES

# Dump Link State Neighbor Table.
1 LS DUMP NEIGHBORS

# Quit the simulator. Commented for now.
#QUIT
