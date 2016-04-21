# Copyright (c) 2010-2013, Regents of the University of California. 
# Copyright (c) 2016 Endress+Hauser
# All rights reserved. 
#  
# Released under the BSD 3-Clause license as published at the link below.
# https://openwsn.atlassian.net/wiki/display/OW/License

import re
import threading


class openConfig(object):
    '''
    Singleton which contains global configurations for openVisalizer
    '''
    
    #===== singleton start
    _instance = None
    _init     = False
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(openConfig, cls).__new__(cls, *args, **kwargs)
        return cls._instance
    #===== singleton stop
    
    def __init__(self):
        
        #===== singleton start
        if self._init:
            return
        self._init = True
        #===== singleton stop
        
        # store params
        self.dataLock   = threading.RLock()
        self.config     = {}
    
    def get(self,*args):
        with self.dataLock:
            if   len(args)==1:
                return self.config.get(args[0])
            elif len(args)==2:
                return self.config.get(args[0],args[1])
            else:
                raise SystemError()
    
    def set(self,name,value):
        with self.dataLock:
            self.config[name] = value
    
    def readFile(self,filename):
        try:
            with open(filename,'r') as f:
                for line in f:
                    line = line.strip()
                    
                    # comments
                    if line.startswith('#'):
                        continue
                    
                    # configuration

                    # match 1 or more non-whitespace chars, which could be by whitespaces chars, 
                    # = required between both strings
                    m = re.search('(\S+)\s*=\s*(\S+)',line)
                    if m:
                        name   = m.group(1)                     # the first parenthesized subgroup.
                        values = m.group(2)                     # the second parenthesized subgroup.
                        
                        if values[0] == ('['):
                            values = values[1:-1].split(',')
                            values = [ int(i[2:],16) for i in values ]
                                                          
                        if len(values)==1:
                            values = values[0]
                        
                        self.set(name,values)
        except IOError:
            print 'no configuration file found, please check !'