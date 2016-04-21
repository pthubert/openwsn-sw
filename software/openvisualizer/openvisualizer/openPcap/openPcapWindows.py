# Copyright (c) 2010-2013, Regents of the University of California. 
# All rights reserved. 
#  
# Released under the BSD 3-Clause license as published at the link below.
# https://openwsn.atlassian.net/wiki/display/OW/License
import logging
log = logging.getLogger('openPcapWindows')
# Do not set the default null log handlers here. Logging already will have been
# configured, because this class is imported later, on the fly, by OpenTun.

import threading
import sys
import re
import netifaces
import pcapy
import pcap

import win32file
import win32event
import pywintypes

import openPcap
from pydispatch import dispatcher
import openvisualizer.openvisualizer_utils as u

#============================ defines =========================================

#============================ helper classes ==================================

class PcapReadThread(threading.Thread):
    '''
    Thread which continously reads input from a pcap interface.
    
    When data is received from the interface, it calls a callback configured
    during instantiation.
    ''' 
    
    def __init__(self,pcapIf,callback):
    
        # store params
        self.adapter              = pcapIf
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
                hdr, pk = self.adapter.next()
                while hdr is not None:
                    self.callback(pk)
                    hdr, pk = self.adapter.next()

            except Exception as err:
                log.error(err)
                pass
            
    #======================== public ==========================================
    
    def close(self):
        self.goOn = False
    
    #======================== private =========================================
    
    
#============================ main class ======================================

class OpenPcapWindows(openPcap.OpenPcap):
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
            self.PcapIf.sendpacket(self.txBuf)             # uses winpcap with pcapy


    def _createPcapIf(self):
        '''
        Open a pcap interface 
        
        :returns: The handler of the interface, which can be used for later
            read/write operations.
        '''
        
        #===== open PCAP adapter
        adapter         = pcapy.open_live(
                            self.adapterName,     # device
                            65536,                # snaplen
                            0,                    # promisc
                            10,                   # to_ms
                            )
        
        #===== apply PCAP filter 
        adapter.setfilter('ip6')

        return adapter
        
                      
    def _createPcapReadThread(self):
        '''
        Creates and starts the thread to read messages arriving from the pcap interface.
        '''
        return PcapReadThread(
            self.PcapIf,
            self._rxpacket_handler
        )
   
    