# Copyright (c) 2010-2013, Regents of the University of California. 
# Copyright (c) 2016 Cisco Systems
# All rights reserved. 
#  
# Released under the BSD 3-Clause license as published at the link below.
# https://openwsn.atlassian.net/wiki/display/OW/License
import logging
log = logging.getLogger('openBBRClient')
log.setLevel(logging.ERROR)
log.addHandler(logging.NullHandler())

import threading
import time

from pydispatch                 import dispatcher
from openvisualizer.openConfig  import openConfig
from openvisualizer.eventBus    import eventBusClient

import openvisualizer.openvisualizer_utils as u
import openvisualizer.iana as IANA_CONSTANTS

  
def carry_around_add(a, b):
    '''
    \brief Helper function for checksum calculation.
    '''
    c = a + b
    return (c & 0xffff) + (c >> 16)

def checksum(byteList):
    '''
    \brief Calculate the checksum over a byte list.
    
    This is the checksum calculation used in e.g. the ICMPv6 header.
    
    \return The checksum, a 2-byte integer.
    '''
    s = 0
    for i in range(0, len(byteList), 2):
        w = byteList[i] + (byteList[i+1] << 8)
        s = carry_around_add(s, w)
    return ~s & 0xffff
 

class openBBRClient(eventBusClient.eventBusClient):
    """
        This is the backbone Router client task
        It interfaces with the ethernet abstraction to get the MAC address and the
        IPv6 linklocal address on that port, and uses them to build NS and RS and
        send them over the ethernet.
        It listens to messages coming from the ethernet and is interested in RA to
        learn the prefix and NA to confirm that NS where processed adequately
        finally, it listens to messages from 6LBR (tbd) and RPL root (new message
        for this project) to learn the registration status. It is expected that the
        RPL root sends
    """ 
    ARO_LIFETIME   = 300  # in sec

    def __init__(self):
    
        # log
        log.info("creating instance")

        # initialize parent class        
        eventBusClient.eventBusClient.__init__(
            self,
            name          = 'openBBRClient',
            registrations = [
                {
                    'sender'        : self.WILDCARD,
                    'signal'        : 'registrationEvent',
                    'callback'      : self._registrationEventNotif
                },
            ]
        )

        # store params
        self.adapterMac     = self._dispatchAndGetResult(
                                signal       = 'getAdapterMac',
                                data         = [],
                              )
        
        s_openConfig            = openConfig.openConfig()
        self.IPV6PREFIX         = s_openConfig.get('OPEN_IPV6PREFIX')
        self.IPV6HOST           = s_openConfig.get('OPEN_IPV6HOST')

        
        # local variables
        self.statsLock          = threading.Lock()
        self.stats              = {}
        self.connectSem         = threading.Lock()
        
        # reset the statistics
        self._resetStats()
        
        # acquire the connectSem, so the thread doesn't start listening
        self.connectSem.acquire()
           
            
    #======================== public ==========================================
    """
        used for testing purpose, do not call directly otherwise
    """
    def newMAC(self,mac):
        if len(mac) == 6:
            self._storeEthernetMAC(mac)
        else:
            print "wrong len for MAC %d" %len(mac)
        
    def getMAC(self):
        mac=self.stats['ethernetMAC'] 
        if mac == None:
            return [0,0,0,0,0,0]
        else:
            return self.stats['ethernetMAC'] 
        
    def newLinkLocal(self,lladdr):
        if len(lladdr) == 16:
            self._storeLinkLocalAddress(lladdr)
        else:
            print "wrong len for Link Local %d" %len(lladdr)
        
    def getLinkLocal(self):
        mac=self.stats['linkLocalAddress'] 
        if mac == None:
            return [0xFE,0x80,0,0,0,0,0,0,
                       0,   0,0,0,0,0,0,1]
        else:
            return self.stats['linkLocalAddress'] 
        
    def createIPv6NeighborSolicitation(self, dst, tgt, uid, tid, lifetime):
        return self._createIPv6NeighborSolicitation(
            self.getMAC(), self.getLinkLocal(), dst, tgt, uid, tid, lifetime)
       
    #======================== private =========================================
  
    #===== Events
    
    def _registrationEventNotif(self,sender,signal,data):
        '''
        Handles a registration event, typically a DAO or no-DAO, or DAR.
                
        This function dispatches the 6LoWPAN ND packet with signal
        'bytesToMesh'.
        '''

        #TODO: get dst from RA and save globally or interface_manager
        dst = [0xfe, 0x80] + [0x00]*6 + [0xfa, 0x72, 0xea, 0xff, 0xfe, 0x83, 0xad, 0xbc]
        tid = int(time.time()/(0.9*60*self.ARO_LIFETIME/60))%128

        try:
            
            ## build NS ARO based on lifetime, uniqueID and Seq counter
            #ns = self.buildGenericNS(lifetime, uid, seq)
            
            ## dispatch
            #self.dispatch(
            #    signal       = 'bytesToMesh',
            #    data         = (ns,ns_bytes),
            #)

            ns = self._createIPv6NeighborSolicitation(self.adapterMac,  # mac
                                                      self.IPV6PREFIX + self.IPV6HOST,  # src,
                                                      dst,
                                                      data,             # tgt
                                                      data[8:],         # uid
                                                      tid,
                                                      self.ARO_LIFETIME # lifetime
                                                      )
            self.dispatch(
                signal      = 'v6ToInternet',
                data        = ns,
            )

        except (ValueError,NotImplementedError) as err:
            log.error(err)
            pass

            
    #===== stats handling
    
    def _resetStats(self,disconnectReason=None):
        
        # log
        if log.isEnabledFor(logging.DEBUG):
            log.debug("resetting stats")
        
        self.statsLock.acquire()
        self.stats['routerAddr']            = None
        self.stats['linkLocalAddress']      = None
        self.stats['prefix']                = None
        self.stats['ethernetMAC']           = None
        self.stats['bytesSentOk']           = 0
        self.stats['packetsSentFailed']     = 0
        self.stats['bytesSentFailed']       = 0
        self.stats['NApacketsReceivedOK']   = 0
        self.stats['RApacketsReceivedOK']   = 0
        self.stats['NSpacketsSentOK']       = 0
        self.stats['RSpacketsSentOK']       = 0
        self.stats['receivedBytes']         = 0
        self.statsLock.release()
        
    def _incrementStats(self,statsName,step=1):
        assert (statsName in ['packetsSentOk',
                              'bytesSentOk',
                              'packetsSentFailed',
                              'bytesSentFailed',
                              'NApacketsReceivedOK',
                              'RApacketsReceivedOK',
                              'NSpacketsSentOK',
                              'RSpacketsSentOK',
                              'receivedBytes'])
        
        self.statsLock.acquire()
        self.stats[statsName] += step
        self.statsLock.release()
        
    def _storePrefix(self,prefix):
        
        self.statsLock.acquire()
        self.stats['prefix'] = prefix
        self.statsLock.release()
        
        # dispatch
        dispatcher.send(
            sender      = 'openBBRClient',
            signal      = 'networkPrefix',
            data        = prefix,
        )

    def _storeEthernetMAC(self,mac):
        
        self.statsLock.acquire()
        self.stats['ethernetMAC'] = mac
        self.statsLock.release()
        
    def _storeLinkLocalAddress(self,lladdr):
        
        self.statsLock.acquire()
        self.stats['linkLocalAddress'] = lladdr
        self.statsLock.release()
       
       

    def _createIPv6NeighborSolicitation(self, mac, src, dst, tgt, uid, tid, lifetime):
        '''
        \brief Create an IPv6 echo request.
        
         See http://tools.ietf.org/html/rfc4861 for ND messages
         See http://tools.ietf.org/html/rfc6282 for ARO option
         See http://tools.ietf.org/html/rfc6550 for TID
         https://tools.ietf.org/html/draft-ietf-6lo-backbone-router for all
        
        :param src:      [in] 16-byte Byte array for the IPv6 source (this node LLA)
        :param dst:      [in] 16-byte Byte array for the IPv6 destination (the BBR)
        :param tgt:      [in] 16-byte Byte array for the IPv6 target (the mote)
        :param uid:      [in]  8-byte Byte array for the mote unique ID (MAC@)
        :param tid:      [in]  1-byte sequence counter
        :param lifetime: [in]  32 bits unsigned in seconds (RFC 6550 route lifetime) 
        
        :raises: ValueError when some part of the process is not defined in
            the standard.
        :raises: NotImplementedError when some part of the process is defined in
            the standard, but not implemented in this module.
        
        :returns: An IPV6 packet with an SLLAO and an ARO option
        '''

        # IANA assigned values stored in a constant class
        IANA = IANA_CONSTANTS.IANA_CONSTANTS()
        IPv6_ND = IANA.IPv6_ND()
                
        # Init a list for the bytestring
        NeighborSolicitation  = []
        
        # IPv6 header
        NeighborSolicitation    += [0x6E,0x00,0x00,0x00]       # version = IPv6, TF
        NeighborSolicitation    += [0x00, 0x30]                # length including ARO option
        NeighborSolicitation    += [IANA.ICMPv6]               # Next header (0x3A ==ICMPv6)
        NeighborSolicitation    += [0xff]                      # HLIM
        NeighborSolicitation    += src                         # source address
        NeighborSolicitation    += dst                         # destination address
        
        # ICMPv6 header  0x87,0x00,0x1e,0x67,0x00,0x00,0x00,0x00,
        NeighborSolicitation    += [IPv6_ND.NS]                # type (135==Neighbor Solicitation)
        NeighborSolicitation    += [0]                         # code
        NeighborSolicitation    += [0x00,0x00]                 # Checksum (to be filled out later)
        NeighborSolicitation    += [0x00,0x00,0x00,0x00]       # Reserved
        
        # Target Address
        NeighborSolicitation    += tgt              # target address
        
        # SLLA option
        NeighborSolicitation    += [IPv6_ND.SLLAO]  # type = source LLA option   
        NeighborSolicitation    += [1]              # Length in group of 8 bytes    
        NeighborSolicitation    += mac              # Ethernet MAC@ of this node
        
        """
              0                   1                   2                   3
               0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              |     Type      |   Length = 2  |    Status     |   Reserved    |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              |   Reserved  |T|     TID       |     Registration Lifetime     |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              |                                                               |
              +         Owner Unique ID   (EUI-64 or equivalent)              +
              |                                                               |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                       0x21,0x02,0x00,0x00,
                       0x01,0x79,0x00,0x05,  TID 0x79 registration for 5mn
                       0xaa,0xbb,0xcc,0xdd,
                       0xee,0xff,0xf5,0x00
     
        """
        # ARO option
        regLifetime = lifetime/60                   # in Minutes
        lifetimeLSB = (regLifetime&0xff)
        lifetimeMSB = (regLifetime&0xff00)>>8
        
        NeighborSolicitation    += [IPv6_ND.ARO]    # type   
        NeighborSolicitation    += [2]              # Length in group of 8 bytes   
        NeighborSolicitation    += [0x00,0x00]      # Status and reserved
        NeighborSolicitation    += [0x01]           # T flag indicating TID present 
        cur = len(NeighborSolicitation)
        NeighborSolicitation    += [tid]            # the TID
        cur = len(NeighborSolicitation)
        NeighborSolicitation    += [0x00,0x00]      # compute the Lifetime
        NeighborSolicitation[cur] = (regLifetime&0xff00)>>8
        cur += 1
        NeighborSolicitation[cur] = (regLifetime&0xff)>>0
        NeighborSolicitation    += uid              # The Unique ID
       
        # calculate ICMPv6 checksum
        pseudo  = src + dst   # concat source address and destination addresses
        pseudo += [0x00]*3+[len(NeighborSolicitation[40:])]    # ULP length
        pseudo += [0x00]*3                          # zero
        pseudo += [58]                              # next header
        pseudo += NeighborSolicitation[40:]         # ICMPv6 header+payload
                
        crc     = checksum(pseudo)                  #  compute checksum
        NeighborSolicitation[42]   = (crc&0x00ff)>>0
        NeighborSolicitation[43]   = (crc&0xff00)>>8
        
        return NeighborSolicitation                 # There you go
    