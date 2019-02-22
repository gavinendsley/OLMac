#
#  proxyClasses.py
#
#  Copyright (c) 2008-2009 Apple, Inc. All rights reserved.
#

#ProtocolServer support
from twisted.protocols import basic
from twisted.protocols import policies
import re, os


from twisted.internet import ssl

from twisted.python import log
from twisted.mail import imap4

from utilities import printDebug,debugClass
from utilities import ExceptionHelperClass

from twisted.mail import smtp

from twisted.internet import interfaces
 
class IMAP4Exception(Exception):
    def __init__(self, *args):
        Exception.__init__(self, *args)

class IllegalClientResponse(IMAP4Exception): pass

class IllegalOperation(IMAP4Exception): pass

class IllegalMailboxEncoding(IMAP4Exception): pass

import commands
from OpenSSL import SSL
class PrivateOpenSSLContextFactory(ssl.DefaultOpenSSLContextFactory):
    CERTADMIN_COMMAND='/usr/sbin/certadmin --get-private-key-passphrase '

    def GetPrivatePassPhraseCB(self, *args):

        passPhrase = ""
        command = PrivateOpenSSLContextFactory.CERTADMIN_COMMAND + self.privateKeyFileName
        (status, passPhrase) = commands.getstatusoutput(command)
        if status != 0:
            message = "Missing passhphrase for certificate key file: " + self.privateKeyFileName
            ExceptionHelperClass.Set(message)
            raise AttributeError

        return passPhrase

    def cacheContext(self):
        ctx = SSL.Context(self.sslmethod)
        ctx.set_passwd_cb(self.GetPrivatePassPhraseCB)
        ctx.set_options(SSL.OP_NO_SSLv2)

        if True == os.path.exists(self.privateKeyFileName): 
            ctx.use_privatekey_file(self.privateKeyFileName)
        else:
            ExceptionHelperClass.Set("parameter ssl_private_key_path=" +self.privateKeyFileName + " not found")
            raise AttributeError
        
        if True == os.path.exists(self.certificateFileName): 
            ctx.use_certificate_file(self.certificateFileName)
        else:
            ExceptionHelperClass.Set("parameter ssl_certificate_path" + self.certificateFileName + "  not found")
            raise AttributeError
            
        self._context = ctx


import time

class AccessLogger():

    logVersions = { 0:'terse', 1:'normal' } 
    version = 1
    transport = { 0:'clear', 1:'ssl', 2:'starttls' } 
    state = { 0: 'unconnected', 1:'client-connected',2: 'proxy-connecting', 3: 'proxy-connected',4: 'proxy-authorized',5: 'server-authorized' } 
    def __init__(self):
        self.entry = {'client':'', 'proxy':'', 'server':'', 'durationsecs': 0 , 'user':'', 'client-authmethod':'', 'proxy-authmethod':'', 'client-transport':'', 'server-transport':'','state': '', 'result':''}
        self.startTimeSeconds =  time.time()
        self.endTimeSeconds = self.startTimeSeconds
        self.receivedChars = 0
        self.proxyAuthorized = False
        self.serverAuthorized = False
        
    def GetLogEntry(self):
        self.endTimeSeconds = time.time()
        self.entry['durationsecs'] = self.endTimeSeconds - self.startTimeSeconds
        self.entry['result'] = self.entry['result'].strip(',')
        if AccessLogger.version > 0: #only two versions right now
            outString = "client:%(client)s, proxy:%(proxy)s, server:%(server)s, connected_secs:%(durationsecs)d, user:%(user)s, client-authmethod:%(client-authmethod)s, proxy-authmethod:%(proxy-authmethod)s, client-transport:%(client-transport)s, server-transport:%(server-transport)s, state:%(state)s, result:%(result)s" % self.entry
        else:
            outString = "%(client)s, %(proxy)s, %(server)s, %(durationsecs)d, %(user)s, %(client-authmethod)s, %(proxy-authmethod)s, %(client-transport)s, %(server-transport)s, %(state)s, %(result)s" % self.entry

        return outString.strip('\r\n\t')

        
class Message():

    len = 0
    msg = ""
    separator = ""
    joined = None
    list = None
    count = 0
    replaceEndings = False
    removeEndings = True
    
    def process(self):
        self.len = len(self.msg)
        self.count = self.len
    
    def __init__(self,msg):
        self.msg = str(msg)
        Message.process(self)
        
    def update(self):
        Message.process(self)

    def join(self, appendStr = ""):
        if self.list != None:
            self.list.append(appendStr)
            self.msg = self.joined = self.separator.join(self.list)
 
        return self.msg
    
class MessageWords(Message):

    wordCount = 0
    words = None
    separator = " "
    
    def process(self):
        self.words = self.list = self.msg.split()
        self.wordCount = self.count = len(self.list)
        self.tag = ""
        if self.wordCount > 0:
            self.tag = self.words[0]
    
    def update(self):
        Message.process(self)
        self.process()


    def __init__(self,msg):
        Message.__init__(self,msg)
        MessageWords.process(self)
        
class MessageLines(Message):

    

    def process(self , keepEndings = True):
        self.lines = self.list = self.msg.splitlines(keepEndings)
        self.lineCount = self.count = len(self.lines)

    def update(self):
        Message.process(self)
        self.process()
        
    
    def __init__(self,msg,keepEndings = True):
    
        self.separator = ""
 
        if keepEndings == Message.replaceEndings:
            self.separator = "\r\n"

        self.lineCount = 0
        self.lines = 0
            
        Message.__init__(self,msg)
        MessageLines.process(self, keepEndings)

class TaggedMessage(MessageLines):
   
   
    def __init__(self,msg):
        MessageLines.__init__(self,msg)
        self.tags = {}
        self.findTags()
        
    def findTags(self):
        for aLine in self.lines:
            messageLine = MessageWords(aLine)
            if messageLine != None and messageLine.wordCount > 1:
                lineID = messageLine.words[0]
                tagStatus = messageLine.words[1].upper()
                if tagStatus == "OK":
                    self.tags[lineID] = True
                else:
                    if tagStatus == "NO" or tagStatus == "BAD":
                       self.tags[lineID] = False
        
    def hasTags(self):
        if len(self.tags) > 0:
            return True
        return False
        
    def process(self):
        MessageLines.process(self)
        self.findTags(self)
        
    def findOKTag(self):   
        for tag in self.tags:
            if self.tags[tag] == True:
                return tag
        return None
        
            
    def tagOK(self, tag):
        if tag in self.tags:
            result =  self.tags[tag]                    
        else:
            result = self.findTag(tag)
            
        return result
        
        
#-----------------------------             
class ProtocolServer(basic.LineReceiver, policies.TimeoutMixin):
    # Command data to be processed when literal data is received
    _pendingLiteral = None
    parseState = 'command'

    def __init__(self, chal = None, contextFactory = None, scheduler = None):
      self._queuedAsync = []

    def connectionMade(self):
        self.tags = {}
        self.canStartTLS = interfaces.ITLSTransport(self.transport, None) is not None
        printDebug( "!!!connectionMade self.canStartTLS =", self.canStartTLS, debugClass.v )
        self.setTimeout(self.timeOut)

    def connectionLost(self, reason):
        self.setTimeout(None)
        if self._onLogout:
            self._onLogout()
            self._onLogout = None

    def timeoutConnection(self):
        self.sendLine('* BYE Autologout; connection idle too long')
        if None != self.transport:
            self.transport.loseConnection()
        self.state = 'timeout'

    def rawDataReceived(self, data):
        self.resetTimeout()
        passon = self._pendingLiteral.write(data)
        if passon is not None:
            self.setLineMode(passon)

    # Avoid processing commands while buffers are being dumped to
    # our transport
    blocked = None

    def _unblock(self):
        commands = self.blocked
        self.blocked = None
        while commands and self.blocked is None:
            self.lineReceived(commands.pop(0))
        if self.blocked is not None:
            self.blocked.extend(commands)

    def sendUntaggedResponse(self, message, async=False):
        if not async or (self.blocked is None):
            self._respond(message, None, None)
        else:
            self._queuedAsync.append(message)

    def lineReceived(self, line):
        if self.blocked is not None:
            self.blocked.append(line)
            return

        self.resetTimeout()

        f = getattr(self, 'parse_' + self.parseState)
        try:
            f(line)
        except Exception, e:
            self.sendUntaggedResponse('BAD Server error: ' + str(e))
            log.err()
            
    def sendLine(self, line):
        """ pure virtual needs implementation
        """
        raise NotImplementedError
        


    def parse_command(self, line):
        args = line.split(None, 1)
        rest = None
        tag = line
        if len(args) > 1:
            cmd, rest = args
        elif len(args) == 1:
            cmd = args[0]
        else:
            self.sendBadResponse(None, 'Null command')
            return None

        cmd = cmd.upper()
        try:
            return self.dispatchCommand(tag, cmd, rest)
        except IllegalOperation, e:
            self.sendBadResponse(tag, 'unknown: ' + str(e))

    def _respond(self, state, tag, message):
        if state in ('OK', 'NO', 'BAD') and self._queuedAsync:
            lines = self._queuedAsync
            self._queuedAsync = []
            for msg in lines:
                self._respond(msg, None, None)
        if not tag:
            tag = '*'
        if message:
            self.sendLine(' '.join((tag, state, message)))
        else:
            self.sendLine(' '.join((tag, state)))
            
    def sendBadResponse(self, tag = None, message = ''):
        self._respond('BAD', tag, message)


    def dispatchCommand(self, tag, cmd, rest, uid=None):
        f = self.lookupCommand(cmd)
        if f:
            fn = f[0]
            parseargs = f[1:]
            self.__doCommand(tag, fn, [self, tag], parseargs, rest, uid)
        else:
            self.sendBadResponse(tag, 'Unsupported command')

    def lookupCommand(self, cmd):
        return getattr(self, '_'.join((self.state, cmd.upper())), None)

    def arg_astring(self, line):
        """
        Parse an astring from the line, return (arg, rest), possibly
        via a deferred (to handle literals)
        """
        line = line.strip()
        if not line:
            raise IllegalClientResponse("Missing argument")
        d = None
        arg, rest = None, None
        if line[0] == '"':
            try:
                spam, arg, rest = line.split('"',2)
                rest = rest[1:] # Strip space
            except ValueError:
                raise IllegalClientResponse("Unmatched quotes")
        elif line[0] == '{':
            # literal
            if line[-1] != '}':
                raise IllegalClientResponse("Malformed literal")
            try:
                size = int(line[1:-1])
            except ValueError:
                raise IllegalClientResponse("Bad literal size: " + line[1:-1])
            d = self._stringLiteral(size)
        else:
            arg = line.split(' ',1)
            if len(arg) == 1:
                arg.append('')
            arg, rest = arg
        return d or (arg, rest)

    # ATOM: Any CHAR except ( ) { % * " \ ] CTL SP (CHAR is 7bit)
    atomre = re.compile(r'(?P<atom>[^\](){%*"\\\x00-\x20\x80-\xff]+)( (?P<rest>.*$)|$)')


#-----------------------------             

        
class ProxyPLAINAuthenticator(imap4.PLAINAuthenticator):
    def challengeResponse(self, secret, chal):
        return '\0%s\0%s' % (self.user, secret)


class ProxyClientAuthBase( smtp.ESMTPClient):
    secret = "secret"
    authMethods = ""
    requireAuthentication = True
    
    def __init__(self, secret = '', contextFactory = None, clientConnection = None):
        smtp.ESMTPClient.__init__(self,secret,  contextFactory, 'foo')
        self.authenticated = False
        self.clientConnection = clientConnection
        self.secret = secret
        
    def _sendLineToServer(self, data):
        raise NotImplementedError

    def _ResponseOK(self,code,resp):
        raise NotImplementedError

    def _ResponseERR(self,code,resp):
        raise NotImplementedError
       
    def _lineReceived(self, line):
         raise NotImplementedError

    def _authenticateWithMethod(self, tag, authName):
        raise NotImplementedError


    def lineReceived(self, line):
        self._lineReceived(line)
            
    def sendLine(self,data):
        self._sendLineToServer(data)
        
    def ResponseERR(self, code, resp):
         self._ResponseERR(code,resp)
        
    def ResponseOK(self, code, resp):
        printDebug("ProxyClient:responseOK OK code=", code, " resp=",resp, debugClass.VV)
        self.authenticated = True
        self.clientConnection.authCheckComplete = True
        self._ResponseOK(code,resp)
  
             
    
    def _authenticateWithNoMethod(self, tag, authMethodToUse):
       if self.requireAuthentication:
              printDebug("ProxyClient->authenticateWithMethod  self.requireAuthentication=True ",  debugClass.VV)                
       else:
            printDebug("ProxyClient->authenticateWithMethod  method=",authMethodToUse,  debugClass.VV)
            if (authMethodToUse == '' and len(self.clientConnection.serverAuthMethods) == 0):
                self.ResponseOK(235,"OK")
            else:
                self.ResponseOK(550,"BAD")
    
    def authenticateWithMethod(self, tag, authMethodToUse):
        printDebug("ProxyClient->authenticateWithMethod authMethodToUse=", authMethodToUse,  debugClass.VV)
        
        if authMethodToUse != "":
            for authMethod in self.authenticators:
                
                authName = authMethod.getName().upper()
                printDebug("ProxyClient->authenticateWithMethod authName=",  authName, "authMethodToUse=", authMethodToUse,  debugClass.VV)
                
                if authName == authMethodToUse:
                    self._authinfo = authMethod
        
                    # Special condition handled
                    self._authenticateWithMethod(tag, authName)
                    return
    
        self._authenticateWithNoMethod(tag, authMethodToUse)
 #-----------------------------             

    
if __name__ == "__main__":
# testing code
    print "test"