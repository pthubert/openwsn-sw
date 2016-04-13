# Copyright (c) 2010-2013, Regents of the University of California. 
# Copyright (c) 2016 Endress+Hauser
# All rights reserved. 
#  
# Released under the BSD 3-Clause license as published at the link below.
# https://openwsn.atlassian.net/wiki/display/OW/License
import logging
log = logging.getLogger('openPcap')
log.setLevel(logging.ERROR)
log.addHandler(logging.NullHandler())

import sys
import re
import netifaces
import pcapy
import pcap

import ctypes
import _winreg as reg
import win32file
import win32event
import pywintypes

from pydispatch                 import dispatcher
from openvisualizer.eventBus    import eventBusClient

import openvisualizer.openvisualizer_utils as u



def getHWparam(interface=None):
    """
    returns the hw information Name and MAC of the given interface, e.g. 'eth0'

    if no interface is given, the function returns the first match for ethx (linux)
    and  pci\ven_8086 (windows, onboard ethernet)
    """
    adapterMac = [0x00]*8
    
    if interface is None:
        adapters = netifaces.interfaces()

        if sys.platform.startswith('win32'):
            ADAPTER_KEY = r'SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}'
            win = ur'pci\ven_8086'  #to be checked with other systems
            with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, ADAPTER_KEY) as devices:
                try:
                    for i in xrange(1000):
                        key_name = reg.EnumKey(devices, i)
                        with reg.OpenKey(devices, key_name) as adapter:
                            try:
                                component_id = reg.QueryValueEx(adapter, 'ComponentId')[0]
                                if win in component_id:
                                    hwkey = reg.QueryValueEx(adapter, 'NetCfgInstanceId')[0]
                                    matches = [adp for adp in adapters if hwkey.encode('utf8') == adp] #get hwkey of matching interfaces
                                    if matches is not None:    
                                        break
                            except WindowsError, err:
                                print err
                                pass
                except WindowsError, err:
                    print err
                    pass

            #retrieve mac addr
            adapterMac = netifaces.ifaddresses(matches[0])[netifaces.AF_LINK][0]['addr']
            #retrieve adapter name
            for iface in pcapy.findalldevs():
                if hwkey.encode('utf8') in iface:
                    adapterName = iface 

        elif sys.platform.startswith('linux'):
            eth = re.compile('eth')
            matches = [adp for adp in adapters if re.match(eth, adp)]
            adapterMac = matches[0]

        else:
            raise NotImplementedError('Platform {0} not supported'.format(sys.platform))

    #interface name is given
    else:
        if sys.platform.startswith('win32'):

            hwkey = '{' + interface.partition('{')[-1].rpartition('}')[0] + '}'
            #retrieve mac addr
            adapterMac = netifaces.ifaddresses(hwkey)[netifaces.AF_LINK][0]['addr']
            #retrieve adapter name
            for iface in pcapy.findalldevs():
                if hwkey in iface:
                    adapterName = iface 

        elif sys.platform.startswith('linux'):
            try:
                adapterMac = open('/sys/class/net/' + interface + '/address').readline()

            except Exception as err:
                print err
                pass

        else:
            raise NotImplementedError('Platform {0} not supported'.format(sys.platform))
    
        
    #format mac addr
    adapterMac = adapterMac.replace(':','').strip()
    adapterMac = u.hex2buf(adapterMac)

    return adapterMac, adapterName

def create():
    '''
    Module-based Factory method to create instance based on operating system
    '''
    # Must import here rather than at top of module to avoid a circular 
    # reference to OpenPcap class.
    
    
    if sys.platform.startswith('win32'):
        from openPcapWindows import OpenPcapWindows
        return OpenPcapWindows()
        
    elif sys.platform.startswith('linux'):
        from openPcapLinux import OpenPcapLinux
        return OpenPcapLinux()
        
    else:
        raise NotImplementedError('Platform {0} not supported'.format(sys.platform))


class OpenPcap(eventBusClient.eventBusClient):
    '''
    Class which interfaces between an ethernet interface and an EventBus.
        
    This class is abstract, with concrete subclases based on operating system.
    '''

    def __init__(self):
        
        #===== initialize
        
        # log
        log.info("creating instance")
        
        # store params
        
                # register to receive outgoing network packets
        eventBusClient.eventBusClient.__init__(
            self,
            name                    = 'OpenPcap',
            registrations           = [
                {
                    'sender'        : self.WILDCARD,
                    'signal'        : 'NStoBBR',
                    'callback'      : self._v6ToInternet_notif,
                },
                {
                    'sender'        : self.WILDCARD,
                    'signal'        : 'v6ToInternet',
                    'callback'      : self._v6ToInternet_notif
                },
            ]
        )

        # local variables
        (
            self.adapterMac,
            self.adapterName
        )                          = getHWparam()

        self.PcapIf                = self._createPcapIf()
        if self.PcapIf:
            self.pcapReadThread  = self._createPcapReadThread()
        else:
            self.pcapReadThread    = None

   
    #======================== public ==========================================

    def close(self):
        
        if self.pcapReadThread:
            
            self.PcapReadThread.close()
    
    #======================== private =========================================
    def _v6ToInternet_notif(self,sender,signal,data):
        '''
        Called when receiving data from the EventBus.
        
        This function forwards the data to the pcap interface.
        Read from 6lowPAN and forward to pcap interface
        '''
        raise NotImplementedError('subclass must implement')
        
                
    def _v6ToMesh_notif(self,data):
        '''
        Called when receiving data from the PCAP interface.
        
        This function forwards the data to the the EventBus.
        Read from pcap interface and forward to 6lowPAN
        '''
        # dispatch to EventBus
        self.dispatch(
            signal        = 'v6ToMesh',
            data          = data,
        ) 

    def _createPcapIf(self):
        '''
        Open a pcap interface
        
        :returns: The handler of the interface, which can be used for later
            read/write operations.
        '''
        raise NotImplementedError('subclass must implement')
        
    def _createPcapReadThread(self):
        '''
        Creates the thread to read messages arriving from the pcap interface
        '''
        raise NotImplementedError('subclass must implement')