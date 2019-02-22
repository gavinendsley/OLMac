#
#  smtpProxyClasses.py
#
#  Copyright (c) 2008-2009 Apple, Inc. All rights reserved.
#

from Queue import Queue
QDontBlock = False
QTimeoutZero = 0
QSize = 5

INITIAL_TIMEOUT= 60 #1 minute
AFTER_VALID_EHLO_TIMEOUT = 120 #2 minutes
AFTER_VALID_AUTH_TIMEOUT = 600 #10 minutes
RESET_TIMEOUT_AFTER_RECEIVED_COUNT = 1024 #chars received

from twisted.internet.defer import maybeDeferred

import ProxyHelper

from utilities import printDebug, debugClass, printDebugStr, ReplaceLineInList,AppendLines,FindLineInStr
from utilities import InConfig, ProxyLog
from utilities import EnvironmentClass

from twisted.python import log
from twisted.protocols.portforward import Proxy
from twisted.protocols.portforward import ProxyClientFactory
import base64
from twisted.internet import protocol
from twisted.internet import reactor
#--------------------------------
from twisted.mail import smtp
import os

#try:
#    from email.base64MIME import encode as encode_base64
#except ImportError:
def encode_base64(s, eol='\n'):
    return s.encode('base64').rstrip() + eol

#--------------------------------
from proxyClasses import ProtocolServer
from proxyClasses import ProxyClientAuthBase
from proxyClasses import AccessLogger

class SMTPException(Exception):
    def __init__(self, *args):
        Exception.__init__(self, *args)


class IllegalClientResponse(SMTPException): pass


RFC2821_OK= { 
"220"                  : "220 Service ready", # connect 
"250"                  : "250 OK",# RSET NOOP AUTH
"221"                  : "221 BYE",
}

RFC2487_OK= { 
"220STARTTLS"          : "220 Ready to start TLS", #STARTTLS
}

RFC3463_OK = { 
"235"                  : "235 2.7.0 Authentication Succeeded",
}

RFC2821_Errors = { 
"421"                  : "421 Service closing transmission channel",  
"500"                  : "500 Syntax error, command unrecognised",
"501"                  : "501 Syntax error in parameters or arguments",
"501EHLO"              : "501 Syntax error: EHLO missing hostname",
"503"                  : "503 Bad sequence of commands",# already auth'd
"503STARTTLS"          : "503 Bad sequence of commands: TLS already negotiated",
"504"                  : "504 Unrecognized authentication type",
"530"                  : "530 Authentication required",
"550"                  : "550 Not implemented",
"554"                  : "554 Transaction failed",
"554STARTTLS"          : "554 Transaction failed. STARTTLS is not available. SSL is enabled",
}

#RFC 4954   SMTP Service Extension for Authentication 
#4.  Required SASL PLAIN (over TLS) as mandatory-to-implement.
#6.  Deprecated the use of the 538 response code.
#Need maximum line length 1000 defensive or 2000 permissive termination of session with send of err 500 (check typical and max line lens before implementing)

RFC3463_Errors = { 
"432"                  : "432 4.7.12 A password transition is needed",
"454STARTTLS"          : "454 4.7.0 Authentication failure: TLS not available",
"454"                  : "454 4.7.0 Authentication failure",
"500AuthLine"          : "500 5.5.6 Authentication failure: line is too long",
"503"                  : "503 5.5.1 Error: already authenticated",
"530"                  : "530 5.7.0 Authentication failure", # AUTH, EHLO, HELO, NOOP, RSET, or QUIT
"530Required"          : "530 5.7.0 Authentication required", # AUTH, EHLO, HELO, NOOP, RSET, or QUIT
"530STARTTLS"          : "530 5.7.0 Authentication failure: Must issue a STARTTLS command first ",# see rfc 4954
"534"                  : "534 5.7.4 Authentication mechanism is invalid",
"535"                  : "535 5.7.8 Authentication failed: credentials invalid",
"535maxtries"          : "535 4.7.0 Authentication failed: too many errors", # security policy error
}


SMTP_OK = RFC2821_OK 
SMTP_OK.update(RFC3463_OK)
SMTP_OK.update(RFC2487_OK)

SMTP_ERR = RFC2821_Errors
SMTP_ERR.update(RFC3463_Errors)

from time import time
MaxUnauthorizedRequests = 10
#-----------------------------             

from mutex import mutex

Start_Seconds = int(time())

Num_Connections = 0
Last_Connections = 0
Last_Seconds = Start_Seconds
statsMutex = mutex()

def statsupdate(proxyServerConnection):
    global Num_Connections
    global Last_Connections
    global Start_Seconds
    global Last_Seconds
    nowSeconds = int(time())
    Num_Connections = Num_Connections + 1
   
    if (nowSeconds % 3 == 0) and (Last_Seconds != nowSeconds) :
        printDebug ("connection count= ", Num_Connections , " avg per sec=" ,  (Num_Connections - Last_Connections) / (nowSeconds - Start_Seconds) )
        Start_Seconds = nowSeconds
        Last_Seconds = nowSeconds
        Last_Connections = Num_Connections

#-----------------------------             
from proxyClasses import ProxyPLAINAuthenticator as smtpPLAINAuthenticator
from twisted.mail.imap4 import CramMD5ClientAuthenticator as smtpCRAMMD5ClientAuthenticator
from twisted.mail.imap4 import LOGINAuthenticator

class smtpLOGINAuthenticator(LOGINAuthenticator):
    def __init__(self, user):
        LOGINAuthenticator.__init__(self,user)
        self.sentUser = False
        self.sentPassword = False

#-----------------------------             
class ProxyESMTPClient(ProxyClientAuthBase):    
    accessLoggerRef = None
   
    def _sendLineToServer(self, data):
        printDebug("ProxyESMTPClient sendLineToServer", data, debugClass.VV)        
        smtp.ESMTPClient.sendLine(self, data)
        
    #make different versions of the response for each auth method
    def _ResponseOK(self, code, resp):
        printDebug("ProxyESMTPClient:_ResponseOK code=", code, " resp=",resp, debugClass.VV)
        self.clientConnection.sendResponseToClient("235", SMTP_OK)
        self.accessLoggerRef.entry['state'] =  AccessLogger.state[5]
      
    def _ResponseERR(self, code, resp):
        printDebug("ProxyESMTPClient:ResponseERR  code=", code, " resp=",resp, debugClass.VV)
        printDebug ("self.clientConnection.MaxUnauthorized=" ,self.clientConnection.MaxUnauthorized,debugClass.vv)
        if (code >= 500 and True == self.clientConnection.EnforceMaxAuthorized() ) :
            return
        else:
            self.clientConnection.writeToClient(" ".join( [str(code), str(resp).strip(),": mail server err\r\n"]))

    def CramMD5ChallengeResponse(self, code, challenge):
#   S: 250 AUTH CRAM-MD5
#   C: AUTH CRAM-MD5
#   S: 334
#      PDg0MTYyLmZIS2ltbklhbkpFbFVNcnouMTIxODE2ODA3NUBtdXJhdGE0LmFwcGxlLmNvbT4=
#   C: Z2cxIDg4ZTRjOGFlYjdhNWU4ODFkMTg0YWVmYWVkNzAwZmRm\r\n
#   S: 235 Authentication successful


        printDebug ("CramMD5ChallengeResponse challenge = ", challenge, "self.secret = ", self.secret, debugClass.vvv)
        try:
            challengeDecoded = base64.decodestring(challenge.strip())
            printDebug ("CramMD5ChallengeResponse challenge.decoded = ", challengeDecoded, "self.secret = ", self.secret, debugClass.vvv)
            challengeResponse = self._authinfo.challengeResponse(self.secret, challengeDecoded)
            b64response = base64.encodestring(challengeResponse).strip()
            printDebug("decodeTest =", base64.decodestring(b64response ), "b64response= ", b64response, debugClass.vvv)
            
        except:
            self.ResponseERR(535, " ProxyClient: Invalid response from server")
            self.transport.loseConnection()
            return
            
        self._okresponse = self.ResponseOK
        self._expected = [235]
        self.sendLine(b64response )
  

    def LoginResponse(self, code, challenge):
#   S: 250 AUTH LOGIN
#   C: AUTH LOGIN
#   S: 334 VXNlcm5hbWU6\\r\n  #base 64 "Username:"
#   C: Z2cx\r\n #base 64 the user's name
#   S: 334 UGFzc3dvcmQ6\r\n #base 64 "Password:"
#   C: Z2cx\r\n #base 64 the user's password
#   S: 235 Authentication successful

        printDebug ("LoginResponse challenge = ", challenge, "self.secret = ", self.secret)
        try:
            challengeDecoded = base64.decodestring(challenge.strip())
            challengeDecoded = challengeDecoded.upper().strip(' \r\n\t:')
            printDebug ("LoginResponse challenge.decoded = ", challengeDecoded, "self.secret = ", self.secret, debugClass.VVV)
            
        except:
            self.transport.loseConnection()
            self.ResponseERR(code, "NO ProxyClient: Invalid response")
            return
        
        printDebug ("LoginResponse challenge OK = ", challengeDecoded, "self.secret = ", self.secret)
         
        challengeResponse = ""
        if challengeDecoded == "USERNAME":
            printDebug ("LoginResponse challenge is USERNAME = ", challengeDecoded, "self.secret = ", self.secret, debugClass.VVV)
            challengeResponse = self._authinfo.challengeUsername(self.secret, challengeDecoded)
            self._authinfo.sentUser = True
        elif challengeDecoded == "PASSWORD":
            challengeResponse = self._authinfo.challengeSecret(self.secret, challengeDecoded)
            self._authinfo.sentPassword = True
        else:
            self.transport.loseConnection()
            self.ResponseERR(code, "NO ProxyClient: Invalid response")
            return
        
        if self._authinfo.sentUser and self._authinfo.sentPassword:
            self._okresponse = self.ResponseOK
            self._expected = [235]
        else:
            self._okresponse = self.LoginResponse
            self._expected = [334]

        printDebug("LoginResponse challenge=", challenge," challengeResponse = ", challengeResponse)
        b64response = base64.encodestring(challengeResponse).strip()
        printDebug("LoginResponse challengeResponse =", base64.decodestring(b64response ), "b64 challengeResponse= ", b64response, debugClass.VVV)

        self.sendLine(b64response)
       
    def _authenticateWithMethod(self, tag, authName):
        # Special condition handled
        printDebug("_authenticateWithMethod: ", tag, " authName: ", authName, debugClass.VVV)
        self.accessLoggerRef.entry['proxy-authmethod'] =  authName
        try:
           if authName  == "CRAM-MD5":
                self._okresponse = self.CramMD5ChallengeResponse
                self._failresponse = self.ResponseERR
                self._expected = [334]
                self.sendLine("AUTH CRAM-MD5")
                
           elif authName  == "LOGIN":
                self._okresponse = self.LoginResponse
                self._failresponse = self.ResponseERR
                self._expected = [334]
                self.sendLine("AUTH LOGIN")

           elif authName  == "PLAIN":
                self._okresponse = self.ResponseOK
                self._failresponse = self.ResponseERR
                self._expected = [235]
                challenge = encode_base64(self._authinfo.challengeResponse(self.secret, 1), eol="")
                self.sendLine("AUTH PLAIN " + challenge )
           else:
                self.transport.loseConnection()
                raise NotImplementedError
           return
        except: 
            self.ResponseERR(550, "Unknown server auth method")

    def _authenticateWithNoMethod(self, tag, authMethodToUse):
        if authMethodToUse == "":
            self.accessLoggerRef.entry['proxy-authmethod'] =  "NONE"
            self.requireAuthentication = False
            self.ResponseOK(235,"auth ok")
            return #ok done processing
        
        #has auth but it is unrecognized
        ProxyClientAuthBase._authenticateWithNoMethod(self, tag, authMethodToUse)
        
    def _lineReceived(self, line):
        smtp.ESMTPClient.lineReceived(self, line)


class SMTPProxyServerParser(ProtocolServer):

        droppedMsg = "_respond message dropped:" 
        def __init__(self):
            self.result = False
            self.allow = False
            self.proxyConnection = None
            self.authCheckComplete = False
            self.dataQ = Queue(QSize) #seems like QSize is reasonable for the client to send when there is no auth response
            self.handled = False
            self.drop = False
            self._transportwrite = None
            self.nextCommand = None
            self.nextAuthMethod = None
            self.old_command = None
            self.haveSTARTTLS = False
            self.sslEnabled = False
            self.STARTTLSEnabled = False
            self.proxyStarttlsEnabled = True
            self.CachedEHLOResponse = None
            self.MaxUnauthorized = MaxUnauthorizedRequests
            self.authClient = None
            self.serverAuthMethods = [] #empty because 'no auth' is a valid method
            self.clientAuthMethods = []
            self.accessLogger = AccessLogger()
            self.lastResetReceivedChars = 0
            
        def process(self):
            return self.authCheckComplete
            
        def _respond(self, state, tag, message):
            if not tag:
                tag = '*'
            if not message:
                msg = ""
                
            msg = ' '.join(( tag, state, message,"\r\n"))            
            self.writeToClient(msg)
            
            printDebug("SMTPProxyServerParser:_respond", msg, debugClass.VV)
        
        def getLookupResponse(self, key, dictionary):
            try: msg = dictionary[key]
            except: msg = "550 Not implemented"
            
            return "".join([msg, "\r\n"] )
        
        def sendResponseWithDomain(self, domain, key, dictionary):
            msg = self.getLookupResponse(key, dictionary)
            if None == domain: 
                domain = ''
            outMsg = msg.replace('<domain>', domain)
            self.writeToClient(outMsg)
           
        def sendResponseToClient(self, key, dictionary):
            msg = self.getLookupResponse(key, dictionary)          
            self.writeToClient(msg)
            self.accessLogger.entry['result'] = msg

        def setConnection(self,connection):
            self.proxyConnection = connection
            
        def setDataToSend(self, data): 
            try:    self.dataQ.put(data,QDontBlock,QTimeoutZero)
            except: return False
            else:   return True

#
        def getDataToSend(self):
            try:    dataToSend = self.dataQ.get(QDontBlock,QTimeoutZero )
            except: return None
            else:   return dataToSend
            
            
        def lineReceived(self, line):
             self.accessLogger.receivedChars= self.accessLogger.receivedChars + len(line)
             self.handled = False
             self.drop = False
             ProtocolServer.lineReceived(self,line)
             #print self.accessLogger.entry['user'], "lineReceived chars=", str(self.accessLogger.receivedChars)
             if False == self.allow and True == self.authCheckComplete:
                 if self.proxyConnection.transport != None:
                    self.proxyConnection.transport.loseConnection()
             if self.allow: #user is authorized so reset timer if we have data
                testChars = self.accessLogger.receivedChars - self.lastResetReceivedChars
                #print self.accessLogger.entry['user'], "chars till next reset=", str(testChars)
                
                if (testChars > RESET_TIMEOUT_AFTER_RECEIVED_COUNT): #don't reset everytime through
                    self.lastResetReceivedChars = self.accessLogger.receivedChars
                    #print self.accessLogger.entry['user'], "resetTimeout", str(self.accessLogger.receivedChars)
                    self.proxyConnection.resetTimeout()
                    self.resetTimeout()

        def sendLine(self, line):
             return self.writeToClient(line)
             
        
        def sendQData(self, sendit = True):
            dataToSend = self.getDataToSend()
            if (sendit) and (self.proxyConnection != None) and (dataToSend != None):
                printDebug("SMTPProxyServerParser->sendQData is passing data to dest server:" ,(dataToSend), debugClass.V)
                try: self.writeToServer(dataToSend)      
                except: pass
            return dataToSend
            
        def sendData(self,dataToSend):
            if (self.proxyConnection != None) and (dataToSend != None):
                printDebug("SMTPProxyServerParser->sendData is passing data to dest server:" , (dataToSend), debugClass.V)
                self.writeToServer(dataToSend)   
             
        def sendAllWaitingData(self):
             while self.sendQData() != None: continue
             
        def dumpAllWaitingData(self):
             while self.sendQData(False) != None: continue



        def locateBestAuthMethod(self):
        
            if (self.serverAuthMethods  != None):
                method = "CRAM-MD5"
                if method in self.serverAuthMethods and method in self.clientAuthMethods:
                    return method
                    
                method = "LOGIN"
                if method in self.serverAuthMethods and method in self.clientAuthMethods:
                    return method
                    
                method = "PLAIN"
                if method in self.serverAuthMethods and method in self.clientAuthMethods:
                    return method
            return ""
            

        def testAuth(self, user,passwd):

            contextFactory = None
            printDebug("testAuth ", user, ":", "xxxx", debugClass.vvv)
            
            if (self.authClient == None):
                self.authClient =  ProxyESMTPClient(passwd,contextFactory, self)
                self.authClient.transport = self.proxyConnection.peer.transport
                self.authClient.accessLoggerRef = self.accessLogger
                if  InConfig('crammd5', self.authToServerConfig) :
                    cAuth = smtpCRAMMD5ClientAuthenticator(user)
                    self.authClient.registerAuthenticator(cAuth)
                    self.clientAuthMethods.append(cAuth.getName().upper())

                if  InConfig('login', self.authToServerConfig) :
                    cAuth = smtpLOGINAuthenticator(user)
                    self.authClient.registerAuthenticator(cAuth)
                    self.clientAuthMethods.append(cAuth.getName().upper())

                if  InConfig('plain', self.authToServerConfig) :
                    cAuth = smtpPLAINAuthenticator(user)
                    self.authClient.registerAuthenticator(cAuth)
                    self.clientAuthMethods.append(cAuth.getName().upper())
            
            if (self.authCheckComplete == False):
                self.authClient.authenticateWithMethod( self, self.locateBestAuthMethod())
#-----------------------------             
       
     
        def authComplete(self, result, param, passwd):
            global statsMutex
            statsMutex.lock(statsupdate, self)
            statsMutex.unlock()
            
            printDebug("SMTPProxyServerParser->authComplete  =" , (result) , " " , (param) , debugClass.V)
            if result == 0:
                self.result = True
                self.allow =  False
                self.accessLogger.entry['state'] =  AccessLogger.state[3]
                printDebug("SMTPProxyServerParser->authComplete login failed for ", param, debugClass.V)
            else:
                self.result = True
                self.allow =  True
                self.accessLogger.proxyAuthorized = True
                self.accessLogger.entry['state'] =  AccessLogger.state[4]
                printDebug("SMTPProxyServerParser->authComplete login success for " + param, debugClass.V)
                if self.proxyConnection.timeOut != AFTER_VALID_AUTH_TIMEOUT:
                    printDebug( param, "setTimeout self.proxyConnection", str(AFTER_VALID_AUTH_TIMEOUT))
                    self.proxyConnection.setTimeout(AFTER_VALID_AUTH_TIMEOUT)
                if self.timeOut != AFTER_VALID_AUTH_TIMEOUT:
                    printDebug( param, "setTimeout SMTPProxyServerParser", str(AFTER_VALID_AUTH_TIMEOUT))
                    self.setTimeout(AFTER_VALID_AUTH_TIMEOUT) 
#-----------------------------  
            printDebug("authComplete", param,"xxxx", debugClass.V)
            if (self.allow and param and passwd):
                self.testAuth(param, passwd)
                return result
            else:
#-----------------------------             
                self.dumpAllWaitingData() #empty the data to send
                printDebug("SMTPProxyServerParser->authComplete user not allowed ", debugClass.V)
                self.sendResponseToClient("535", SMTP_ERR)
                self.proxyConnection.transport.loseConnection()
                
            return result  
      
      
        def do_LOGIN(self, tag, user, passwd):
            if user != None:
                self.accessLogger.entry['user'] =  user
           
            try: ipaddressStr = str(self.proxyConnection.transport.getPeer()[1])
            except: passwd == None
            
            printDebug( "SMTPProxyServerParser->do_LOGIN user=" , (user) , " passwd=" , ("xxxx"), " Service=SMTP ipaddress= ",ipaddressStr,  debugClass.V)
            if user == None or passwd == None:
                self.authComplete(0, user, passwd)
            else:
                maybeDeferred(ProxyHelper.authenticateAndAuthorizeUser, user, passwd,"SMTP", ipaddressStr ).addCallback(self.authComplete, user,passwd) 
                
        def parse_LOGIN(self, tag, cmd, rest):
           printDebug( "SMTPProxyServerParser->parse_LOGIN tag=", (tag) , " cmd=" , (cmd), " rest=" ,(rest),  debugClass.VV)        
           (authType, rest) =  self.arg_astring(rest)
           (user, rest) = self.arg_astring(rest)
           (passwd, rest) = self.arg_astring(rest)
           return self.do_LOGIN(tag,user,passwd)
            
        def do_PLAIN(self, tag, authMethod,authString):
            #c: "AUTH PLAIN AHRlc3QwAHRlc3Q=" #test0
            #c: "AUTH PLAIN AGdnMQBnZzE=" #gg1
            #c: "AUTH PLAIN AGdnMgBnZzI=" #gg2
            #s: "235 2.0.0 Authentication Successful\r\n"
            #   or some clients do the following
            #c: "AUTH PLAIN"
            #s: "334\r\n"
            #c: "AHRlc3QwAHRlc3Q="
            #testdata = "AUTH PLAIN AHRlc3QwAHRlc3Q="
            #authString = testdata
            printDebug("do_PLAIN string=", authString,  debugClass.VV)
            try:
                decodedString = base64.decodestring(authString)
            except Exception, e:
                return self.do_LOGIN(tag, None,None)
                
                
            fields = decodedString.split("\0")
            user = fields [1:2]
            passwd = fields [2:3]  
            
            if user == []: 
                user = [""]
            
            if passwd == []: 
                passwd = [""]
            
            if (len(decodedString) > 0 and user == [""] and passwd == [""]):
                #have string but no user:pass
                return self.do_LOGIN(tag, None,None)
                
            if (user == [""] and passwd == [""]):
                self.nextCommand = "AUTH"
                self.nextAuthMethod = "PLAIN"
                self.old_command = self.parse_command
                self.parse_command = self.next_command
                self.writeToClient("334\r\n") #waiting for user:pass
                self.dumpAllWaitingData()
                return
             
            self.do_LOGIN(tag, user[0], passwd[0])
            
        def do_AUTHENTICATE(self, tag, authMethod, rest):
            if authMethod != None:
                authMethod = authMethod.upper()
                
            if authMethod == "PLAIN":
                self.accessLogger.entry['client-authmethod'] =  "PLAIN"
                self.do_PLAIN(tag, authMethod, rest)
            else:
                self.do_UNSUPPORTED(tag,authMethod, rest)
              
        def parse_AUTHENTICATE(self, tag, cmd, rest): 
            if rest == None:
                return self.sendResponseToClient("534", SMTP_ERR)
                
            (authMethod, rest) = self.arg_astring(rest)
            printDebug( "SMTPProxyServerParser->parse_AUTHENTICATE authMethod=" , authMethod , debugClass.VV)
            
            return self.do_AUTHENTICATE(tag,authMethod, rest)
            
        def do_EHLO(self, tag, cmd, rest):
            printDebug("tag=", tag, "cmd=", cmd, "rest=", rest, debugClass.VV)
            if rest == None:
                return self.sendResponseToClient("501EHLO", SMTP_ERR)
                
             
            if self.CachedEHLOResponse != None:
                printDebug("do_EHLO send cached EHLO response", self.CachedEHLOResponse)
                self.writeToClient(self.CachedEHLOResponse)
                return
                
            tag = "".join( [tag,"\r\n"] ) #add required line ending
            printDebug( "SMTPProxyServerParser->do_EHLO with line ending [", (tag) , "] cmd=" , (cmd) , " rest=" , (rest),  debugClass.VV)
            self.writeToServer(tag)     
            
            self.handled = True
            
            return
        
        def do_QUIT(self,tag,cmd,rest):
            printDebug("tag=", tag, "cmd=", cmd, "rest=", rest, debugClass.VV)
            return self.sendResponseToClient("221", SMTP_OK)
          
        def do_RSET(self,tag,cmd,rest):
            printDebug("tag=", tag, "cmd=", cmd, "rest=", rest, debugClass.VV)
            return self.sendResponseToClient("250", SMTP_OK)
            
            
        def do_STARTTLS(self, tag, cmd, rest):
            # We should not be called here.
            self.handled = True
            self.drop = True #don't pass through
            return
        
        
                            
        def do_UNSUPPORTED(self, tag, cmd, rest):
            printDebug( "SMTPProxyServerParser->do_UNSUPPORTED " , (tag) , " " , (cmd) , " " , (rest),  debugClass.VV)
            # self.sendBadResponse(tag, 'Unsupported command')
            
            self.drop = True #don't pass through
            self.dumpAllWaitingData()
            self.handled = True
            if False == self.sslEnabled and False == self.STARTTLSEnabled:
                errMessage =  "530STARTTLS" 
            else:
                errMessage = "530Required"
            
            self.sendResponseToClient(errMessage, SMTP_ERR)

        def parse_command(self, line):
            printDebug( "SMTPProxyServerParser->parse_command line=", (line),  debugClass.VV )
            if self.authCheckComplete:
                printDebug(  "SMTPProxyServerParser parse_command nothing to do leaving"  , debugClass.VV)
                return
            ProtocolServer.parse_command(self, line)
          
        def next_command(self, line):
            if (self.old_command != None):
               self.parse_command = self.old_command
            printDebug( "SMTPProxyServerParser->next_command line=", (line),  debugClass.VV )
            #if self.authCheckComplete:
            #    printDebug(  "SMTPProxyServerParser parse_command nothing to do leaving"  , debugClass.VV)
            #    return
            self.dumpAllWaitingData()
            self.do_PLAIN(self.nextCommand, self.nextAuthMethod, line)
        
        def EnforceMaxAuthorized(self):       
            if 0  < self.MaxUnauthorized:
                self.MaxUnauthorized -= 1 
                return False
            
            self.sendResponseToClient("535maxtries", SMTP_ERR)    
            if (self.proxyConnection != None): 
                self.proxyConnection.transport.loseConnection()
                
            return True
           
        def dispatchCommand(self, tag, cmd, rest, uid=None):
            if False == self.allow:
                if True == self.EnforceMaxAuthorized():
                    return
                    
            printDebug(  "SMTPProxyServerParser dispatchCommand tag=" , (tag) , " cmd=" , (cmd) , " rest=" , (rest)  , debugClass.VV)

            printDebug(  "SMTPProxyServerParser dispatchCommand self.sslEnabled=", self.sslEnabled," self.haveSTARTTLS =", self.haveSTARTTLS, " self.proxyStarttlsEnabled=", self.proxyStarttlsEnabled, debugClass.VV)
            allowAuthCommand = True
            if False == self.sslEnabled and (False == self.haveSTARTTLS and True == self.proxyStarttlsEnabled):
                allowAuthCommand = False
 

            if False == allowAuthCommand:
                ourCommands = { "EHLO": "do_EHLO",
                                "QUIT": "do_QUIT",
                                "RSET": "do_RSET",
                              }
            else:
                ourCommands = { "EHLO": "do_EHLO",
                                "AUTH": "parse_AUTHENTICATE",
                                "QUIT": "do_QUIT",
                                "RSET": "do_RSET",
                              }
            default = 'do_UNSUPPORTED'
            
            action = ourCommands.get(cmd, default)
            printDebug(  "cmd=" , (action), debugClass.VV )
            
            dispatch = getattr(self, action, None)
            if dispatch:
                try:
                    dispatch(tag, cmd, rest)
                except:
                    log.err()
 

        def isValidEHLOResponse(self, lines):
            lastLine = len(lines)
            foundvalidLine = False
            for index, aLine in enumerate(lines):
                printDebug("isValidEHLOResponse line=", aLine, "index =",index, "lastLine = ", lastLine, debugClass.VV)
                if "250-" != aLine[:4]:
                    if (aLine[:4]== "250 " and index == lastLine -1):
                        printDebug("last line of EHLO is valid =", aLine, debugClass.VV)
                        return True #last line must be "250" followed by a space
                    return False
            return False
            
        def processEHLOResponse(self, lines, data):
            outData = data
            
           
            if True == self.sslEnabled:
                supportSTARTTLS = False #use SSL
                self.accessLogger.entry['client-transport'] =  AccessLogger.transport[1]
            elif True == self.proxyStarttlsEnabled: 
                supportSTARTTLS = True #use start tls
            else:  
                supportSTARTTLS = False #no ssl or tls
                
            if len(lines) > 1 and self.drop == False :
                emptyLine = ""
                           
                if  True == self.STARTTLSEnabled or False == supportSTARTTLS: #ok tls has started or we are not doing starttls so show them the auth
                    (foundAuth, lines) = ReplaceLineInList("250-AUTH", "250-AUTH PLAIN\r\n", True , lines)
                    if False == foundAuth:
                        lines.insert(1,"250-AUTH PLAIN\r\n")
                else:
                    (foundAuth, lines) = ReplaceLineInList("250-AUTH", emptyLine, True , lines)

                printDebug("foundAuth=", foundAuth, debugClass.VV)
                ##PrintThing(lines)
                
                #remove any entries
                foundStartTLS = False
                if (True == supportSTARTTLS and False == self.STARTTLSEnabled): 
                    (foundStartTLS, lines) = ReplaceLineInList("250-STARTTLS", emptyLine ,True, lines)
                printDebug("foundStartTLS=", foundStartTLS, debugClass.VV)
                ##PrintThing(lines)
                
                #only send if we haven't started and we support it
                if (False == self.STARTTLSEnabled and True == supportSTARTTLS): 
                    #insert after the first entry -- test for num lines above
                    lines.insert(1,"250-STARTTLS\r\n")
                outData = AppendLines(lines)
                self.CachedEHLOResponse = outData
                
         
            return outData
            
        def writeToClient(self,data):
            outData = data
            s = str(data)  
            self.accessLogger.entry['result'] = s
            if "250-" == s[:4]:
                lines = s.splitlines(True)
                if data != self.CachedEHLOResponse and self.isValidEHLOResponse(lines):
                    dataNoCRLF = data.strip()
                    self.serverAuthMethods = FindLineInStr("250-AUTH", dataNoCRLF).split(" ")
                    if self.serverAuthMethods == '':
                        self.serverAuthMethods = FindLineInStr("250 AUTH", dataNoCRLF)
                    printDebug("serverAuthMethods",self.serverAuthMethods , debugClass.VV)
                    outData = self.processEHLOResponse(lines, data)
                    
                    if self.proxyConnection.timeOut != AFTER_VALID_EHLO_TIMEOUT:
                        self.proxyConnection.setTimeout(AFTER_VALID_EHLO_TIMEOUT) 
                        printDebug ("SMTPProxyServerParser:writeToClient setTimeout=",  self.proxyConnection.timeOut, debugClass.VV )


            printDebug( "SMTPProxyServerParse->write to client final:" , (outData) , debugClass.VV)
            if None != self._transportwrite:
                self._transportwrite(outData)
            self.drop = False


        def writeToServer(self,data):
        
            #testerr
            #import time
            #print "Sleep 30"
            #time.sleep(30)
            
            if self.proxyConnection.peer.transport is not None:
                self.proxyConnection.peer.transport.write(data)     




class SMTPProxyProtocol(Proxy):
 
    def setPeer(self, peer):
        self.peer = peer

    def dataReceived(self, data):
        printDebug("SMTPProxyProtocol:dataReceived=", data, debugClass.VV)
        if self.peer.transport is not None:
            self.peer.transport.write(data)
        
        
        
class SMTPProxy(SMTPProxyProtocol):
    noisy = True

    peer = None
    tlsStarted= False
    canStartTLS = False
    hasStartTLS = False
    tlsState = 0
    connectState = 0
    mailClient = None
    proxyClient = None
    cachedConnectMessage = None
    context = None
    mailServerTransport = None
    mailClientTransport = None
    accessLoggerRef = None

    def setPeer(self, peer):
        self.peer = peer
          
    def connectionLost(self, reason):
        #The proxy-server connection
        printDebug("SMTPProxy: connectionLost : %s" % (reason,),debugClass.v)
        
        if self.accessLoggerRef != None:
            tracebackInfo = "%s" %  (reason,)
            if tracebackInfo.find("filedescriptor",0,len(tracebackInfo)) != -1:
                self.accessLoggerRef.entry['result'] = "Server Connection closed by internal error (EMFILE). " 
                ProxyLog.LogErrSMTP( "PID (", os.getpid(), ") readFDs (", len(reactor._reads), ") writeFDs (",  len(reactor._writes),")  filedescriptor out of range" , " err =", "EMFILE")
            elif self.accessLoggerRef.entry['state'] !=  AccessLogger.state[5]:
                self.accessLoggerRef.entry['result'] = "Server connection closed unexpectedly. " 
            else:
                self.accessLoggerRef.entry['result'] = "Server connection closed."
        
        if self.peer is not None: #the client connection
            self.peer.transport.loseConnection()
            
            self.mailClient = self.peer = None
        elif self.noisy:
            if self.accessLoggerRef is not None:
                printDebug("SMTPProxy: accessLoggerRef[result] was =", self.accessLoggerRef.entry['result'], " is now= ", str(reason.value), debugClass.V)
                self.accessLoggerRef.entry['result'] =  "Server connection closed unexpectedly. " 
            printDebug("SMTPProxy: Unable to connect to peer: %s" % (reason,),debugClass.v)
            
    def createContextFactory(self):
        if self.context is not None:
            return self.context
            
        try: from twisted.internet import ssl
        except: return None

        self.context = ssl.ClientContextFactory()
        self.context.method = ssl.SSL.TLSv1_METHOD
        return self.context

    def getTestEHLOData(self):
        #test code as if generated by a test server
        comment, data = "No 250-STARTTLS", "250-g5.local\r\n250-PIPELINING\r\n250-SIZE 10485760\r\n250-VRFY\r\n250-ETRN\r\n250-AUTH LOGIN PLAIN CRAM-MD5\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250 DSN\r\n"
        comment, data = "No 250-STARTTLS and No 250-AUTH", "250-g5.local\r\n250-PIPELINING\r\n250-SIZE 10485760\r\n250-VRFY\r\n250-ETRN\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250 DSN\r\n"
        comment, data = "everything", "250-g5.local\r\n250-PIPELINING\r\n250-SIZE 10485760\r\n250-VRFY\r\n250-ETRN\r\n250-AUTH LOGIN PLAIN CRAM-MD5\r\n250-STARTTLS\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250 DSN\r\n"
        printDebug("TEST INPUT ", comment, ": SMTPProxy:dataReceived state=",self.tlsState," data=", data, debugClass.VV)
        return data
    
    
    def dataReceived(self, data):
        printDebug("SMTPProxy:dataReceived state=",self.tlsState," data=", data, debugClass.VV)
        
        if self.tlsState > 4: #the most common case first
            if (self.peer.smtpServer.authClient and False == self.peer.smtpServer.authClient.authenticated) : 
                self.peer.smtpServer.authClient.lineReceived(data)
            else:
                if self.peer.transport is not None:
                    self.peer.transport.write(data) #write to client
        elif 0 == self.tlsState:  #initialize the connection with the server        
            self.cachedConnectMessage = data
            self.transport.write("EHLO SecurityProxyServer\r\n") # test for starttls on the server      
            self.tlsState = 1
        elif 1 == self.tlsState:   

#           data = self.getTestEHLOData() #get test data for ehlo response
            if data.find("STARTTLS") != -1:
                self.transport.write("STARTTLS\r\n")   
                self.tlsState =2
                self.hasStartTLS = True
            else:
                self.tlsState =3
                if self.peer.transport is not None:
                    self.peer.transport.resumeProducing()
                    self.peer.transport.write(self.cachedConnectMessage) #write to client
                 
        elif 2 == self.tlsState:
            self.createContextFactory()
            from twisted.internet import interfaces
            tls = interfaces.ITLSTransport(self.transport, None)
            printDebug("startTls with self.context=", self.context," tls= ", tls, debugClass.vvv)
             
            #testerr
            #import time
            #print "Sleep 30"
            #time.sleep(30)
            
            self.transport.startTLS(self.context)
            self.tlsStarted = True
            if self.accessLoggerRef != None:
                self.accessLoggerRef.entry['server-transport'] = AccessLogger.transport[2]
                
            self.tlsState =3
            if self.peer.transport is not None:
                self.peer.transport.resumeProducing()
                self.peer.transport.write(self.cachedConnectMessage) #write to client
        elif 3 == self.tlsState or 4 == self.tlsState:

            if self.transport.TLS and not self.hasStartTLS and self.accessLoggerRef != None:
                self.accessLoggerRef.entry['server-transport'] = AccessLogger.transport[1]

            if (self.peer.smtpServer.authClient and False == self.peer.smtpServer.authClient.authenticated) : 
                self.peer.smtpServer.authClient.lineReceived(data)
            else:               
                self.tlsState = 5
                if self.peer.transport is not None:
                    self.peer.transport.write(data) #write to client


class SMTPProxyClient(SMTPProxy):  
    host = "securityproxy_mail"
    
    def connectionMade(self):    
        '''
            self.transport is the connection to the mail server
            self.transport.write 
            self.peer.transport is the connection back to the mail client 
            self.peer.transport.write --> SMTPProxyServerParser.writeToClient
        '''
        # We're connected, everybody can read to their hearts content.         
        
        self.peer.setTimeout(INITIAL_TIMEOUT)
        printDebug( "SMTPProxyClient:connectionMade timeOut= ", self.peer.timeOut, debugClass.VV )
    
        self.peer.setPeer(self)
        self.proxyClient = self.transport
        self.accessLoggerRef = self.peer.smtpServer.accessLogger
        self.peer.smtpServer.accessLogger.entry['state'] =  AccessLogger.state[3]
        if self.accessLoggerRef != None:
            self.accessLoggerRef.entry['server-transport'] = AccessLogger.transport[0]
          

class SMTPProxyClientFactory(ProxyClientFactory):

    protocol = SMTPProxyClient
    def setServer(self, server):
        self.server = server

    def buildProtocol(self, *args, **kw):
        prot = protocol.ClientFactory.buildProtocol(self, *args, **kw)
        prot.setPeer(self.server)
        return prot

    def clientConnectionFailed(self, connector, reason):
        self.server.transport.loseConnection()

ConnectionCounts = {}

class SMTPProxyServer(SMTPProxy):

    clientProtocolFactory = SMTPProxyClientFactory
    accessLogged = False
    
    def myLoseConnection(self):
        if False == self.accessLogged:
            self.accessLogged = True
            #PrintThing(self.smtpServer.accessLogger)
            keepPreviousResult = True
            if  -1 != self.smtpServer.accessLogger.entry['result'].find("BAD", 0 , 5) :  # Result is A generic connection failure. Replace it.
                keepPreviousResult = False
                self.smtpServer.accessLogger.entry['result'] = ""
                
            if self.smtpServer.accessLogger.entry['client-authmethod'] ==  "": #no valid authenticate from client. expects PLAIN
                self.smtpServer.accessLogger.entry['result'] = "No valid auth method from client. Verify that client and server are configured for mobile access. " + self.smtpServer.accessLogger.entry['result']
                keepPreviousResult = True
                    
            prefixStr = ""                
            if self.smtpServer.accessLogger.entry['state'] ==  AccessLogger.state[4] and  self.smtpServer.accessLogger.receivedChars > 0 and  self.smtpServer.accessLogger.serverAuthorized == False:
                prefixStr = "BAD. User not authorized by mail server. "
            elif self.smtpServer.accessLogger.entry['state'] ==  AccessLogger.state[2] and  self.smtpServer.accessLogger.receivedChars == 0:
                prefixStr = "BAD. Proxy failed connection with mail server. "
            elif self.smtpServer.accessLogger.entry['state'] ==  AccessLogger.state[3] and  self.smtpServer.accessLogger.proxyAuthorized == False  and  self.smtpServer.accessLogger.serverAuthorized == False:
                prefixStr = "BAD. User not authorized by proxy server. "
            elif self.smtpServer.accessLogger.receivedChars == 0:
                self.smtpServer.accessLogger.entry['state'] =  AccessLogger.state[0]
                prefixStr = "BAD. User failed connection with proxy server. "
            elif self.smtpServer.accessLogger.entry['state'] !=  AccessLogger.state[5]:
                 prefixStr = "BAD. Lost connection. "
            else:
                prefixStr = "OK. "
            
            previousResult = self.smtpServer.accessLogger.entry['result']
            if True == keepPreviousResult:
                self.smtpServer.accessLogger.entry['result'] = prefixStr + previousResult.replace(",", "." ) 
            else:
                 self.smtpServer.accessLogger.entry['result'] = prefixStr
            ProxyLog.LogAccSMTP(self.smtpServer.accessLogger.GetLogEntry())
        self.transportLoseConnection() #close the client to proxy connection
        
        if self.peer is not None: #close the proxy to server connection
            if self.peer.transport is not None:
                self.peer.transport.loseConnection()
      
    def checkMaxConnectionLimit(self):
        numReadFDs = len(reactor._reads)
        #print "checkMaxConnectionLimit PID=%d read FDs=%d MaxFDs=%d ConnectionLimit=%d " % (os.getpid(), numReadFDs , EnvironmentClass.MaxFDs, EnvironmentClass.ConnectionLimit )
        printDebugStr( 0, "checkMaxConnectionLimit PID=%d read FDs=%d MaxFDs=%d ConnectionLimit=%d " ,os.getpid(), numReadFDs , EnvironmentClass.MaxFDs, EnvironmentClass.ConnectionLimit )
        if numReadFDs > EnvironmentClass.ConnectionLimit:
            printDebug( "checkMaxConnectionLimit reactor.self._reads =" , numReadFDs, " > ConnectionLimit =", EnvironmentClass.ConnectionLimit)
            self.smtpServer.accessLogger.entry['result'] = "Proxy maximum connection limit reached PID(%d) FDs(%d)." % (os.getpid(), numReadFDs)
            ProxyLog.LogErrSMTP( self.smtpServer.accessLogger.entry['result'] , " err =", "EMFILE")
            self.transport.loseConnection()
            return True
        return False
        
    def connectionMade(self):
         # Don't read anything from the connecting client until we have
        # somewhere to send it to.
        self.setTimeout(self.timeout)
        printDebug("SMTPProxyServer:connectionMade setTimeout=",self.timeout, debugClass.VV)
        self.transport.pauseProducing()

        self.transportLoseConnection = self.transport.loseConnection
        self.transport.loseConnection = self.myLoseConnection

        client = self.clientProtocolFactory()
        client.setServer(self)

        if False == self.checkMaxConnectionLimit():
            reactor.connectTCP(self.factory.host, self.factory.port, client)
            self.smtpServer.accessLogger.entry['server'] =  str(self.factory.host) + ":" + str(self.factory.port)
            self.smtpServer.accessLogger.entry['state'] =  AccessLogger.state[2]
            self.smtpServer.accessLogger.entry['result'] =  "BAD. Couldn't connect to server."
            if self.transport.TLS:
                self.smtpServer.accessLogger.entry['client-transport'] = AccessLogger.transport[1]
            else:
                self.smtpServer.accessLogger.entry['client-transport'] = AccessLogger.transport[0]
        
        self.smtpServer.accessLogger.entry['client'] =  str(self.transport.getPeer()[1])+":"+ str(self.transport.getPeer()[2])
        self.smtpServer.accessLogger.entry['proxy'] =  str(self.transport.getHost()[1])+":"+ str(self.transport.getHost()[2])



from twisted.mail.protocols import ESMTPFactory
class ESMTPProxyFactory(ESMTPFactory):

    proxy_ssl_enabled = False

    def __init__(self, dest_address, dest_port, sslContext, *args):
        ESMTPFactory.__init__(self, None, None, *args)
        self.host = dest_address
        self.port = dest_port
        self.context = sslContext

    def buildProtocol(self, addr):
        p = ESMTPFactory.buildProtocol(self, addr)
        p.sslEnabled = self.proxy_ssl_enabled
        p.authToServerConfig = self.auth_to_server
        p.proxyStarttlsEnabled = self.proxy_starttls_enabled
        return p

from twisted.mail.smtp import ESMTP
class SMTPProxyServerClass(ESMTP, SMTPProxyServer):

            
    def __init__(self, chal = None, contextFactory = None):
        self.smtpServer = SMTPProxyServerParser()
        
        self.ctx = contextFactory
        self.mode = None
        self.sslEnabled = False
        self.authToServerConfig = []
        self.proxyStarttlsEnabled = True
        printDebug("SMTPProxyServerClass init sslEnabled=", (self.sslEnabled ), " proxyStarttlsEnabled=", self.proxyStarttlsEnabled)
    
    def connectionMade(self):            
        SMTPProxyServer.connectionMade(self)
        self.smtpServer.sslEnabled = self.sslEnabled #flag smtpServer not to starttls if ssl is on
        self.smtpServer.proxyStarttlsEnabled = self.proxyStarttlsEnabled #flag smtpServer to disable starttls
        printDebug("SMTPProxyServerClass connectionMade sslEnabled=", (self.sslEnabled ), " proxyStarttlsEnabled=", self.proxyStarttlsEnabled)
      
        self.smtpServer.authToServerConfig = self.authToServerConfig
        printDebug("SMTPProxyServerClass connectionMade authToServerConfig=", (self.authToServerConfig) )
        
        self.smtpServer.setConnection(self)
        printDebug("SMTPProxyServerClass->connectionMade from client:", str(self.transport.getPeer()), " to proxy:", str(self.transport.getPeer().host)   )
        peer = self.transport.getPeer()
        try:
            host = peer.host
        except AttributeError: # not an IPv4Address
            host = str(peer)
        self._helo = (None, host)

        self.smtpServer._transportwrite = self.transport.write
        self.transport.write = self.smtpServer.writeToClient
        if self.accessLoggerRef != None:
            self.accessLoggerRef.entry['server-transport'] = AccessLogger.transport[2]

    def connectionLost(self, reason): 
        #The client-proxy connection
        printDebug("SMTPProxyServerClass: connectionLost : %s" % (reason,),debugClass.v)
        tracebackInfo = "%s" %  (reason,)
        if tracebackInfo.find("filedescriptor",0,len(tracebackInfo)) != -1:
            self.smtpServer.accessLogger.entry['result'] = "Server internal error. %s"  %  tracebackInfo
            ProxyLog.LogErrSMTP( "PID (", os.getpid(), ") readFDs (", len(reactor._reads), ") writeFDs (",  len(reactor._writes),")  filedescriptor out of range" , " err =", "EMFILE")
        elif tracebackInfo.find("SSL",0,len(tracebackInfo)) != -1:
            self.smtpServer.accessLogger.entry['result'] = "Client STARTTLS failed (possible SSLv2 attempt)."
        else:
            self.smtpServer.accessLogger.entry['result'] = "Client disconnected."
        if self.transport != None:
            self.transport.loseConnection()
                                
    def timeoutConnection(self):
        msg = '%s Timeout error, service closing transmission channel' % (self.host)
        self.sendCode(421, msg)
        self.smtpServer.accessLogger.entry['result'] = msg
        self.transport.loseConnection()
        
    def ext_STARTTLS(self, rest):        
        message = "none"
        messageType = SMTP_ERR
        printDebug ("ext_STARTTLS self.sslEnabled =", (self.sslEnabled), debugClass.VV)
        
        if  True == self.sslEnabled: #ERR ssl is configured no STARTTLS
            messageType = SMTP_ERR
            message= "554STARTTLS"
             
        elif self.startedTLS: #ERR TLS already started
            messageType = SMTP_ERR
            message= "503STARTTLS"
             
        elif self.ctx: #OK ready to start tls
            messageType = SMTP_OK
            message= "220STARTTLS"
             
        else:
            messageType = SMTP_ERR
            message= "454STARTTLS"
              
        
        self.smtpServer.sendResponseToClient(message, messageType)    
        printDebug( "SMTPProxyServerClass->ext_STARTTLS to client: ",  message , debugClass.V )

        if SMTP_OK == messageType :
            self.transport.startTLS(self.ctx)
            self.startedTLS = True
            self.smtpServer.STARTTLSEnabled = True
            self.smtpServer.CachedEHLOResponse = None #reset the cache to allow AUTH methods through to the client.

    def dataReceived(self, data):      
        printDebug("SMTPProxyServerClass->dataReceived=", data, debugClass.VV)
  
        isSTARTTLS = -1
        commandStr = str(data)
        lowerStr = commandStr.lower()
        lenth = len(commandStr)
        isSTARTTLS =  lowerStr.find("starttls",0,10)
        if (self.smtpServer.haveSTARTTLS == False and isSTARTTLS >= 0 and lenth == 10):
            printDebug("SMTPProxyServerClass->dataReceived isSTARTTLS: Client Sent STARTTLS", debugClass.VV)
            self.ext_STARTTLS(data)
            self.smtpServer.haveSTARTTLS = True
            self.smtpServer.accessLogger.entry['client-transport'] =  AccessLogger.transport[2]
            self.smtpServer.drop = False
        else:
            printDebug("SMTPProxyServerClass->dataReceived notSTARTTLS", debugClass.VV)
            self.smtpServer.setDataToSend(data)
            self.smtpServer.dataReceived(data)
        
            if self.smtpServer.authCheckComplete:
                printDebug( "SMTPProxyServerClass->dataReceived allow:" , (self.smtpServer.allow) , debugClass.VV)
                if (self.smtpServer.allow == True):
                    printDebug( "SMTPProxyServerClass->dataReceived passing data to dest server:" , (data), debugClass.VV)
                    self.smtpServer.writeToServer(data)
                else:
                    printDebug( "SMTPProxyServerClass->dataReceived not allowed data not sent:" , (data), debugClass.VV)
                    if self.transport != None:
                        self.transport.loseConnection()
    
            else:
                if not self.smtpServer.handled:
                    if (lenth <= 6):
                        isQUIT =  lowerStr.find("quit",0,4)
                        if (isQUIT >= 0):
                            self.smtpServer.sendResponseToClient("221", SMTP_OK)
                            if self.transport != None:
                                return self.transport.loseConnection()

                        isNOOP =  lowerStr.find("noop",0,4)
                        if (isNOOP >= 0):
                            return self.smtpServer.sendResponseToClient("250", SMTP_OK)
                             
                        if (lenth <= 2):
                            isEmpty = False
                            if (lowerStr[0] == '\r' or lowerStr[0] == '\n') :
                                isEmpty = True
                        
                            if ( isEmpty):
                                self.smtpServer.sendResponseToClient("500", SMTP_ERR)
                        
                    printDebug("SMTPProxyServerClass->dataReceived auth check not complete waiting to send data:" , debugClass.VV)

        if self.smtpServer.drop:
            self.smtpServer.dumpAllWaitingData()
             
