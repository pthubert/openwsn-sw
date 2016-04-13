# Copyright (c) 2010-2013, Regents of the University of California. 
# All rights reserved. 
#  
# Released under the BSD 3-Clause license as published at the link below.
# https://openwsn.atlassian.net/wiki/display/OW/License
import logging
log = logging.getLogger('openPcapLinux')
# Do not set the default null log handlers here. Logging already will have been
# configured, because this class is imported later, on the fly, by OpenTun.

import threading
import sys
import re
import netifaces
import pcapy
import pcap

import openPcap
from pydispatch import dispatcher
import openvisualizer.openvisualizer_utils as u

#============================ defines =========================================

MAC_BROADCAST       = [0x33,0x33,0x00,0x00,0x00,0x01]
ETHERTYPE_IPv6      = [0x86,0xdd]

LEN_HDR_ETH         = 6+6+2
LEN_HDR_IPv6        = 40
#============================ helper classes ==================================

class PcapReadThread(threading.Thread):
    '''
    Thread which continously reads input from a TUN interface.
    
    When data is received from the interface, it calls a callback configured
    during instantiation.
    '''
        
    def __init__(self,adapter,callback):
    
        # store params
        self.adapter
        self.callback             = callback
        
        # local variables
        self.goOn                 = True
        
        # initialize parent
        threading.Thread.__init__(self)
        
        # give this thread a name
        self.name                 = 'PcapReadThread'
        
        # start myself
        self.start()
    
    def run(self):
    
        while self.goOn:    
            try:
                for ts,pk in self.adapter:
                    self._rxpacket_handler(pk)

            except Exception as err:
                log.error(err)
                pass
            
    #======================== public ==========================================
    
    def close(self):
        self.goOn = False
    
    #======================== private =========================================

    
#============================ main class ======================================

class OpenPcapLinux(openPcap.OpenPcap):
    '''
    Class which interfaces between a pcap interface and an EventBus.
    '''
    
    def __init__(self):
        # log
        log.info("create instance")
        
        # initialize parent class
        openPcap.OpenPcap.__init__(self)
    
    #======================== public ==========================================
    
    #======================== private =========================================
    
    def _v6ToInternet_notif(self,sender,signal,data):
                
        with self.datalock:
            self.txBuf = ''
            self.txBufFill = 0
            
            # ethernet header

            # destination           
            self._addToTxBuff(self.MAC_BROADCAST)
            # source
            self._addToTxBuff(self.adapterMac)
            # ethertype
            self._addToTxBuff(self.ETHERTYPE_IPv6)

            # payload
            self._addToTxBuff(data)
            
            # send
            self.adapter.inject(self.txBuf,self.txBufFill)  # works with linux pypcap


    def _createPcapIf(self):
        '''
        Open a pcap interface 
        
        :returns: The handler of the interface, which can be used for later
            read/write operations.
        '''                        

        #===== open PCAP adapter
        adapter    = pcap.pcap('eth0')
        
        #===== apply PCAP filter 
        adapter.setfilter('ip6')

        return adapter


    def _createPcapReadThread(self):
        '''
        Creates and starts the thread to read messages arriving from the pcap interface.
        '''
        return PcapReadThread(
            self._v6ToMesh_notif
        )
   
    #======================== helpers =========================================
    

    def _addToTxBuff(self,bytes):
        for b in bytes:
            self.txBuf += chr(b)
            self.txBufFill += 1
    
    def _rxpacket_handler(self,pk):
        
        payload = [ord(b) for b in pk]

        # parse Ethernet

        if len(payload)<self.LEN_HDR_ETH:
            print 'parse ERROR 1'
            return

        eth_destination      = payload[0:6]
        eth_source           = payload[6:12]
        eth_type             = payload[12:14]

        payload              = payload[self.LEN_HDR_ETH:]    # cutoff ethernet header

        if eth_type==self.ETHERTYPE_IPv6:

            #if payload[40] == 0x80:
            #    print '\nEcho Request '

            #elif payload[40] == 0x81:
            #    print '\nEcho Reply '

            #elif payload[40] == 0x86:
            #    print '\nRouter Advertisement'

            #elif payload[40] == 0x87:
            #    print '\nNeigbor Solicitation '

            #elif payload[40] == 0x88:
            #    print '\nNeighbor Advertisement '

            #elif payload[40] == 0x89:
            #    print '\nRedirect '

            #else:
            #    print '\nType unknown'


            self.callback(payload)

        #if eth_source==self.adapterMac:
        #    print 'parse ERROR 2'
        #    return
       
        ## parse IPv6
       
        #if len(payload)<self.LEN_HDR_IPv6:
        #    print 'parse ERROR 3'
        #    return

        #ipv6_full            = payload

        #ip_version           = payload[0]&0xf0>>4
        #ip_traffic_class     = (payload[0]&0x0f<<4) | (payload[1]&0xf0>>4)
        #ip_flow_label        = (payload[1]&0x0f<<16) | (payload[2]<<8) | payload[3]
        #ip_payload_length    = (payload[2]<<4) | payload[5]
        #ip_next_header       = payload[6]
        #ip_hop_limit         = payload[7]
        #ip_source            = payload[8:24]
        #ip_destination       = payload[24:40]

        #payload              = payload[self.LEN_HDR_IPv6:]
        
        #if len(payload)!=ip_payload_length:
        #    print 'parse ERROR 4'
        #    return
        
        #if   ip_next_header==self.IPPROTO_ICMPv6:
        #    proto       = 'icmpv6'
        #elif ip_next_header==self.IPPROTO_UDP:
        #    proto       = 'udp'
        #else:
        #    print 'parse ERROR 5'
        #    return
        
        #packet = {
        #    'ethernet': {
        #        'source':         eth_source,
        #        'destination':    eth_destination,
        #    },
        #    'ipv6_full':          ipv6_full,
        #    'ipv6': {
        #        'version':        ip_version,
        #        'traffic_class':  ip_traffic_class,
        #        'flow_label':     ip_flow_label,
        #        'payload_length': ip_payload_length,
        #        'next_header':    ip_next_header,
        #        'hop_limit':      ip_hop_limit,
        #        'source':         ip_source,
        #        'destination':    ip_destination,
        #    },
        #    'payload':            payload,
        #}
        
        ## dispatch received packet
        #dispatcher.send(
        #    signal      = 'ipv6FromInternet_{0}'.format(proto),
        #    data        = packet,
        #)