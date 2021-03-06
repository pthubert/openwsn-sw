'''
This is a functional test which verify the correct behavior of the OpenTun.
The test involves 3 components:
- the openTun element under test, which sits on the EvenBus
- the ReadThread, implemented in this test module, which listens for ICMPv6
  echo request packets, and answers with an echo reply packet.
- the WriteThread, implemented in this test module, which periodically sends
  an echo reply. The expected behavior is that, for each echo request sent by
  the writeThread, an echo reply is received by the readThread.

Run this test by double-clicking on this file, then pinging any address in the
prefix of your tun interface (e.g. 'ping bbbb::5').
'''

import sys
import os
if __name__=='__main__':
    here = sys.path[0]
    sys.path.insert(0, os.path.join(here, '..', '..','eventBus','PyDispatcher-2.0.3'))# PyDispatcher-2.0.3/
    sys.path.insert(0, os.path.join(here, '..', '..'))                                # openvisualizer/

import threading
import time
import traceback
import openvisualizer.openvisualizer_utils as u


from openvisualizer.eventBus import eventBusClient
from openBBRClient import openBBRClient

#============================ defines =========================================

#============================ helpers =========================================
'''

eg NS(ARO):
-----------
0x6e,0x00,0x00,0x00,0x00,0x30,0x3a,0xff,
0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0xa8,0xbb,0xcc,0xff,0xfe,0x01,0xf5,0x00,
0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
0x87,0x00,0x9f,0x39,0x00,0x00,0x00,0x00,
0x20,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0xa8,0xbb,0xcc,0xff,0xfe,0x01,0xf5,0x00,
0x01,0x01,0xaa,0xbb,0xcc,0x01,0xf5,0x00,
0x21,0x02,0x00,0x00,0x01,0x79,0x00,0x05,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0xf5,0x00
 
eg NA with ARO option status OK
---------------------------------
0x6e,0x00,0x00,0x00,0x00,0x28,0x3a,0xff,
0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0xa8,0xbb,0xcc,0xff,0xfe,0x01,0xf5,0x00,
0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
0x88,0x00,0x9c,0x62,0xa0,0x00,0x00,0x00,
0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0xa8,0xbb,0xcc,0xff,0xfe,0x01,0xf5,0x00,
0x21,0x02,0x00,0x00,0x01,0x79,0x00,0x44,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0xf5,0x00,
   
'''

#============================ test cases ============================================
def testGenNSARO():
    '''
    \brief calls inner functions to generate an NS ARO and checks result
    '''

    msgToGenerate = [                           0x6e,0x00,0x00,0x00,0x00,0x30,0x3a,0xff,
        0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0xa8,0xbb,0xcc,0xff,0xfe,0x01,0xf5,0x00,
        0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
        0x87,0x00,0x9f,0x39,0x00,0x00,0x00,0x00,
        0x20,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0xa8,0xbb,0xcc,0xff,0xfe,0x01,0xf5,0x00,
        0x01,0x01,0xaa,0xbb,0xcc,0x01,0xf5,0x00,
        0x21,0x02,0x00,0x00,0x01,0x79,0x00,0x05,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0xf5,0x00]
       
    client = openBBRClient.openBBRClient()
    client.newMAC(msgToGenerate[66:72])
    client.newLinkLocal(msgToGenerate[8:24])
  
    dst         = msgToGenerate[24:40]
    tgt         = msgToGenerate[48:64]
    tid         = msgToGenerate[77]
    lifetimemn  = 256 * msgToGenerate[78]
    lifetimemn += msgToGenerate[79]
    lifetimes   = 60 * lifetimemn
    uid         = msgToGenerate[80:88]
  
    msg=client.createIPv6NeighborSolicitation(dst, tgt, uid, tid, lifetimes)
  
    if msgToGenerate == msg:
        print "\nSuccess!\n"
        return 0
    else: 
        print "\nKO :(\n"
        print "", msgToGenerate , "of length %d 0x%X" % (len(msgToGenerate),len(msgToGenerate))
        print "generated"
        print "", msg , "of length %d 0x%X" % (len(msg),len(msg))
        return 1
  

#============================ main ============================================

def main():
   print "->Test gen NS ARO"
   rc=testGenNSARO()
   
if __name__ == '__main__':
    main()
