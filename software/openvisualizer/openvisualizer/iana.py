def constant(f):
    def fset(self, value):
        raise TypeError
    def fget(self):
        return f()
    return property(fget, fset)

class IANA_CONSTANTS(object):
    '''
    \brief Implements IANA constants
    # http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml 
    ''' 
    @constant
    def ICMPv6():
        return 58

    class IPv6_ND(object):
    
        @constant
        def RS():
            return 133
            
        @constant
        def RA():
            return 134
            
        @constant
        def NS():
            return 135
            
        @constant
        def NA():
            return 136
            
        @constant
        def SLLAO():
            return 1
            
        @constant
        def TLLAO():
            return 2
            
        @constant
        def ARO():
            return 33
  