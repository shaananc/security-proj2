* PENNSEARCH VERBOSE ALL ON
* PENNSEARCH VERBOSE TRAFFIC OFF
* PENNSEARCH VERBOSE DEBUG OFF

#------ converge routing protocol ------#
TIME 60000

#------------ build chord ring -------------#
0 PENNSEARCH CHORD JOIN 0
TIME 10000
1 PENNSEARCH CHORD JOIN 0
TIME 10000
2 PENNSEARCH CHORD JOIN 1
TIME 10000
3 PENNSEARCH CHORD JOIN 2
TIME 10000
4 PENNSEARCH CHORD JOIN 3
TIME 10000
5 PENNSEARCH CHORD JOIN 4
TIME 10000
6 PENNSEARCH CHORD JOIN 0
TIME 10000
7 PENNSEARCH CHORD JOIN 2
TIME 10000
8 PENNSEARCH CHORD JOIN 5
TIME 10000
9 PENNSEARCH CHORD JOIN 0
TIME 10000
10 PENNSEARCH CHORD JOIN 7
TIME 10000
11 PENNSEARCH CHORD JOIN 2
TIME 10000
12 PENNSEARCH CHORD JOIN 10
TIME 10000
13 PENNSEARCH CHORD JOIN 9
TIME 10000
14 PENNSEARCH CHORD JOIN 8
TIME 10000
15 PENNSEARCH CHORD JOIN 3
TIME 10000
16 PENNSEARCH CHORD JOIN 5
TIME 10000
17 PENNSEARCH CHORD JOIN 12
TIME 10000
18 PENNSEARCH CHORD JOIN 15
TIME 10000
19 PENNSEARCH CHORD JOIN 14
TIME 10000

#--------------- well-formed ring(ring_size = 20) ---------------#
3 PENNSEARCH CHORD RINGSTATE
TIME 5000
QUIT
#--------------- graceful leaving ---------------#

11 PENNSEARCH CHORD LEAVE
TIME 10000
19 PENNSEARCH CHORD LEAVE
TIME 10000
3 PENNSEARCH CHORD LEAVE
TIME 10000
8 PENNSEARCH CHORD LEAVE
TIME 10000
18 PENNSEARCH CHORD LEAVE
TIME 10000

#--------------- well-formed ring(ring_size = 15) ---------------#
15 PENNSEARCH CHORD RINGSTATE
TIME 5000

#--------------- add nodes to the ring ---------------#
11 PENNSEARCH CHORD JOIN 5
TIME 10000
19 PENNSEARCH CHORD JOIN 14
TIME 10000
3 PENNSEARCH CHORD JOIN 6
TIME 10000
8 PENNSEARCH CHORD JOIN 10
TIME 10000 
18 PENNSEARCH CHORD JOIN 0
TIME 10000

#--------------- well-formed ring(ring_size = 20) ---------------#
0 PENNSEARCH CHORD RINGSTATE
TIME 5000

QUIT
