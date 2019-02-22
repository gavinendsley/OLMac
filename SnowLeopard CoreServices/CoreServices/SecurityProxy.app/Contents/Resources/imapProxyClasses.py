#
#  imapProxyClasses.py
#
#  Copyright (c) 2008-2009 Apple, Inc. All rights reserved.
#


from twisted.protocols.portforward import Proxy
from twisted.protocols.portforward import ProxyFactory
from twisted.protocols.portforward import ProxyClientFactory


from twisted.internet.defer import maybeDeferred
from twisted.internet import protocol
from twisted.internet import reactor 

from twisted.python import log
from twisted.mail.imap4 import IMAP4Server        
import ProxyHelper

from utilities import printDebug,debugClass,debugStr,printDebugStr, ReplaceInList, ReplaceLineInStr
from utilities import InConfig, ProxyLog, Truncate
from utilities import EnvironmentClass

from twisted.mail.imap4 import IllegalServerResponse

from proxyClasses import ProxyClientAuthBase
from proxyClasses import TaggedMessage, MessageLines, MessageWords, Message
from proxyClasses import ProxyPLAINAuthenticator as imapPLAINAuthenticator

from proxyClasses import AccessLogger
from proxyClasses import IllegalClientResponse,IllegalOperation, IllegalMailboxEncoding

import base64
import os


from twisted.mail.imap4 import LOGINAuthenticator
from twisted.mail.imap4 import CramMD5ClientAuthenticator as imapCRAMMD5ClientAuthenticator


class imapLOGINAuthenticator(LOGINAuthenticator):
    def __init__(self, user):
        LOGINAuthenticator.__init__(self,user)
        self.sentUser = False
        self.sentPassword = False
        

class imapCLEARAuthenticator(imapPLAINAuthenticator):

    def needsBackSlashesAndQuotes(self,inString):
        '''
        before sending a clear text password to the server, see if it has any special chars
        spaces in a string need quotes around the string
        double quotes need a \ prepended
        backslash needs a \ prepended
        indicate that \ characters should be removed and or spaces are contained by adding quotes around string
        '''
        if None == inString:
            return False
            
        inStringLen = len(inString)
        if inStringLen < 1: #quote an empty value
            return True
            
        #spaces or " or \ need special handling: put quotes around and add a \ to \ and " chars
        space = inString.find(" ",0 ,inStringLen )
        quote = inString.find("\"", 0,inStringLen)
        backSlash = inString.find("\\",0,inStringLen)        
        if (quote > -1) or (backSlash > -1) or (space > -1):
            return True
            
        return False
        
    def insertBackSlashesAndQuotes(self, string):
        newstring = string.replace('\\', "\\\\") 
        newstring = newstring.replace('\"', "\\\"") 
        newstring = "\"%s\"" % ( newstring )
        return newstring
        
    def __init__(self, user):
        self.user = user

    def getName(self):
        return "CLEAR"

    def challengeResponse(self, secret, chal):
        newSecret = secret
        newUser = self.user
        
        if True == self.needsBackSlashesAndQuotes(newSecret):
            newSecret = self.insertBackSlashesAndQuotes(newSecret)
             
        if True == self.needsBackSlashesAndQuotes(newUser):
            newUser = self.insertBackSlashesAndQuotes(newUser)
        
        return "%s %s" % (newUser, newSecret)

class ProxyIMAP4Client(ProxyClientAuthBase):
    maxChallengeLen = 1000
    
    def sendLineToServer(self, data):
        #printDebug("ProxyIMAP4Client sendLineToServer", data, debugClass.VVV)        
        self.clientConnection.writeToServer( data)

    #make different versions of the response for each auth method
    def _ResponseOK(self,code,resp):
        self.clientConnection.writeToClient(resp)
        self.accessLoggerRef.serverAuthorized=True
        self.accessLoggerRef.entry['result'] =  resp
        self.accessLoggerRef.entry['state'] =  AccessLogger.state[5]
        #PrintThing(self.accessLoggerRef)

    def ResponseERR(self, code, resp):
        self.accessLoggerRef.entry['result'] =  resp
        printDebug("ProxyIMAP4Client:ResponseERR code=", code, " resp=",resp, debugClass.VV)
        self.clientConnection.writeToClient(resp)
        return
       
    def _isLineOK(self, line):
        messageLines = TaggedMessage(line)
        isOK  = False
        
        try:
            isOK = messageLines.hasTags()
            self.code = messageLines.findOKTag()

        except ValueError:
            # This is a fatal error that shouldn't happen and will one day disconnect the transport lineReceived will not be called again
            printDebug("Invalid response from IMAP server: ", line,  debugClass.VV)
            self.transport.loseConnection()
        
        return isOK
       
    def _isChallengeOK(self, line):
        challengeParsed = MessageWords(line)
        #testerr
        #challengeParsed.wordCount = 0
        try:
            if challengeParsed.wordCount == 0: 
                raise ValueError
            
            if challengeParsed.wordCount < 2 or challengeParsed.wordCount > 2:  
                raise ValueError
                
            
            if challengeParsed.words[0] != '+':
                raise ValueError
            
            
            if len(challengeParsed.words[1]) < 1:
                raise ValueError
                
            if challengeParsed.len > ProxyIMAP4Client.maxChallengeLen:
                 raise ValueError
           
            self.code = challengeParsed.words[0]
            
             
            return True
        
        except ValueError:
            printDebug("Invalid response from IMAP server: ", line,  debugClass.VV)
            self.transport.loseConnection()
      
    def _isCramMD5ChallengeOK(self, line):           
        return self._isChallengeOK(line)
        
    def _isLoginChallengeOK(self, line):           
        return self._isChallengeOK(line)
        
    def _isPlainChallengeOK(self, line):           
        challengeParsed = MessageWords(line)
        #testerr
        #challengeParsed.wordCount = 0
        try:
            if challengeParsed.wordCount == 0: 
                raise ValueError

# looks like it is possible that a server might send a text message following the +            
#           if challengeParsed.wordCount != 1:  
#                raise ValueError
            
            if challengeParsed.words[0] != '+':
                raise ValueError
            
            if challengeParsed.len > ProxyIMAP4Client.maxChallengeLen:
                 raise ValueError
           
            self.code = challengeParsed.words[0]
            
            return True
        
        except ValueError:
            # This is a fatal error that shouldn't happen and will one day disconnect the transport lineReceived will not be called again
            printDebug("Invalid response from IMAP server: ", line,  debugClass.VV)
            self.transport.loseConnection()
     

    def IsLineOK(self, line):
        return self._isLineOK(line)
       

    def lineReceived(self, line):
        printDebug("ProxyIMAP4Client->lineReceived = ", line, debugClass.VV)
        self.resetTimeout()
        
        why = None        
        messageLines = TaggedMessage(line)
        
        isOK = self.IsLineOK(line)
        printDebug("ProxyIMAP4Client->lineReceived self.code: ", self.code,  debugClass.VV)

        if self.code in self._expected and isOK:
            why = self._okresponse(self.code,line)
        else:
            why = self._failresponse(self.code,line)

        self.code = -1
        self.resp = []
        return why

    def CramMD5ChallengeResponse(self, code, challenge):
#   S: * OK IMAP4 Server
#   C: A0001 AUTHENTICATE CRAM-MD5\r\n
#   S: + PDg0MTYyLmZIS2ltbklhbkpFbFVNcnouMTIxODE2ODA3NUBtdXJhdGE0LmFwcGxlLmNvbT4=
#   C: Z2cxIDg4ZTRjOGFlYjdhNWU4ODFkMTg0YWVmYWVkNzAwZmRm\r\n
#   S: A0001 OK CRAM authentication successful


        printDebug ("CramMD5ChallengeResponse challenge = ", challenge, "self.secret = ", self.secret,  debugClass.VVV)
        parsedMessage = MessageWords(challenge)
        challenge = parsedMessage.words[1]
        try:
            challenge = base64.decodestring(challenge)
            printDebug ("CramMD5ChallengeResponse challenge.decoded = ", challenge, "self.secret = ", self.secret,  debugClass.VVV)
            challengeResponse = self._authinfo.challengeResponse(self.secret, challenge)
            b64response = base64.encodestring(challengeResponse).strip()
            printDebug("decodeTest =", base64.decodestring(b64response ), "b64response= ", b64response,  debugClass.VVV)
            
        except:
            self.transport.loseConnection()
            self.ResponseERR(code, "NO ProxyClient: Invalid response")
            return
            
        self.IsLineOK = self._isLineOK
        self._okresponse = self.ResponseOK
        self.sendLineToServer(b64response + '\r\n')
 
    def LoginResponse(self, code, challenge):
#   S: * OK IMAP4 Server
#   C: 1.29 AUTHENTICATE LOGIN\r\n
#   S: + VXNlcm5hbWU6\\r\n  #base 64 "Username:"
#   C: Z2cx\r\n #base 64 the user's name
#   S: + UGFzc3dvcmQ6\r\n #base 64 "Password:"
#   C: Z2cx\r\n #base 64 the user's password
#   S: 1.29 OK [CAPABILITY IMAP4 etc etc ] Success (no protection)\r\n'

        printDebug ("LoginResponse challenge = ", challenge, "self.secret = ", self.secret, debugClass.VVV)
        parsedMessage = MessageWords(challenge)
        challenge = parsedMessage.words[1]
        stripChars = ' \r\n\t:'
        try:
            challenge = base64.decodestring(challenge).upper().strip(stripChars)
            printDebug ("LoginResponse challenge.decoded = ", challenge, "self.secret = ", self.secret, debugClass.VVV)
            
        except:
            self.transport.loseConnection()
            self.ResponseERR(code, "NO ProxyClient: Invalid response")
            return
            
        if challenge == "USERNAME":
            challengeResponse = self._authinfo.challengeUsername(self.secret, challenge)
            self._authinfo.sentUser = True
        elif challenge == "PASSWORD":
            challengeResponse = self._authinfo.challengeSecret(self.secret, challenge)
            self._authinfo.sentPassword = True

        if self._authinfo.sentUser and self._authinfo.sentPassword:
            self.IsLineOK = self._isLineOK
            self._okresponse = self.ResponseOK
        else:
            self.IsLineOK = self._isLoginChallengeOK
            self._okresponse = self.LoginResponse

        printDebug("LoginResponse challenge=", challenge," challengeResponse = ", challengeResponse, debugClass.VVV)
        b64response = base64.encodestring(challengeResponse).strip()
        printDebug("LoginResponse challengeResponse =", base64.decodestring(b64response ), "b64 challengeResponse= ", b64response, debugClass.VVV)

        self.sendLineToServer(b64response + '\r\n')

    def PlainResponse(self, code, challenge):
#   C: 1.29 AUTHENTICATE PLAIN\r\n
#   S: + \\r\n 
#   C: AGdnMQBnZzE=\r\n # base 64 <NUL>name<NUL>password
#   S: 1.29 OK

        printDebug ("PlainResponse challenge = ", challenge, "self.secret = ", self.secret, debugClass.VVV)
        parsedMessage = MessageWords(challenge)
        challengeResponse = self._authinfo.challengeResponse(self.secret, challenge)        
        printDebug("PlainResponse challenge=", challenge," challengeResponse = ", challengeResponse)
        b64 = base64.encodestring(challengeResponse).strip()
        self.sendLineToServer(b64 + '\r\n')
        self.IsLineOK = self._isLineOK
        self._okresponse = self.ResponseOK
    
    
    def _authenticateWithMethod(self, tag, authName):
        # Special condition handled
        #test
        #authName  = "xxx"
        printDebug("_authenticateWithMethod: ", tag, " authName: ", authName, debugClass.vv)
        try:
            if authName  == "CRAM-MD5":
                self.IsLineOK = self._isCramMD5ChallengeOK
                self._okresponse = self.CramMD5ChallengeResponse
                self._failresponse = self.ResponseERR
                self._expected = ['+', tag]               
                self.sendLineToServer(tag + " AUTHENTICATE CRAM-MD5\r\n")
                
            elif authName  == "PLAIN":
                self.IsLineOK = self._isPlainChallengeOK   
                self._okresponse = self.PlainResponse
                self._failresponse = self.ResponseERR
                self._expected = ['+', tag]                
                challenge = self._authinfo.challengeResponse(self.secret, 1) 
                self.sendLineToServer(tag + " AUTHENTICATE PLAIN\r\n")
                
            elif authName  == "LOGIN":
                self.IsLineOK = self._isLoginChallengeOK   
                self._okresponse = self.LoginResponse
                self._failresponse = self.ResponseERR
                self._expected = ['+', tag]                
                challenge = self._authinfo.challengeResponse(self.secret, 1) 
                self.sendLineToServer(tag + " AUTHENTICATE LOGIN\r\n")
                
            elif authName  == "CLEAR":
                self._okresponse = self.ResponseOK
                self._failresponse = self.ResponseERR
                self._expected = [tag]                
                challenge = self._authinfo.challengeResponse(self.secret, 1) 
                self.sendLineToServer(tag + " LOGIN " + challenge +"\r\n")
                
            else:
                # If some error occurs here, the server declined the AUTH
                # before the user / password phase. This would be
                # a very rare case
                self.transport.loseConnection()
                raise IllegalServerResponse(tag)
                
                            
            self.accessLoggerRef.entry['proxy-authmethod'] =  authName
            return
        except: 
            self.accessLoggerRef.entry['proxy-authmethod'] =  "Unknown. "+ Truncate(str(authName), 20)
            self.ResponseERR(tag, "NO ProxyClient: Unknown auth method. ")
           

#-----------------------------             






from Queue import Queue
QDontBlock = False
QTimeoutZero = 0
MaxInProcessListSize = 5
QSize = 5


class CapabilityMsg(MessageWords):
    yesDeleteDups = True
    
    def __init__(self, msg):
        MessageWords.__init__(self,msg)
        self.authMethods = []
        self.isCAPABILITYResponse = False
        self.isOKInitialResponse = False
        self.isBAD = False
        
        
    def processAuthMethods(self):
#test        if self.isCAPABILITYResponse:
#test            self.msg = self.msg + " LOGINDISABLED "
        printDebug("processAuthMethods in:",self.msg, debugClass.VV)
        AUTHfoundList = []
        aLineAuth = []
        foundDISABLED = []
        logindisabledFound = False
        starTLSFound = False
        msgLines = MessageLines(self.msg, Message.replaceEndings)
        if msgLines.lineCount == 0:
            return
            
        for index in range (0, msgLines.lineCount):
            
            aLine = msgLines.lines[index]
            wordsInLine = MessageWords(aLine)
            if wordsInLine != None:
               (authFound, wordsInLine.words, aLineAuth ) = ReplaceInList( "AUTH=", '',self.yesDeleteDups,  wordsInLine.words, extractFoundList = True, caseInsensitive = True)
               AUTHfoundList = AUTHfoundList + aLineAuth
               if (logindisabledFound == False):
                    (logindisabledFound, wordsInLine.words, foundDISABLED) = ReplaceInList( "LOGINDISABLED", '', self.yesDeleteDups,  wordsInLine.words,extractFoundList = True)
               (starTLSFound, wordsInLine.words, foundList) = ReplaceInList( "STARTTLS", '', self.yesDeleteDups,  wordsInLine.words,extractFoundList = False)
               msgLines.lines[index] = wordsInLine.join().strip( ' \r\n\t')
               
        self.msg = msgLines.join()
        self.msg = self.msg.strip( ' \r\n\t')
        self.msg = self.msg.replace('(no protection)', '') #server sends this when using non-ssl transport but it doesn't apply in this case
        self.msg = self.msg.replace("   ", ' ') # remove extra white space
        self.msg = self.msg.replace("  ", ' ')# remove extra white space
        
        if authFound or starTLSFound:
           self.msg = self.msg + "]"
        
        printDebug("processAuthMethods out:",self.msg, debugClass.VV)        
        self.msg = self.msg + "\r\n"
        self.authMethods = AUTHfoundList + foundDISABLED
        printDebug("CapabilityMsg AUTHfoundList:", AUTHfoundList, " authMethods:",self.authMethods, debugClass.VV)
       
    def processResponse(self):
        if self.wordCount > 2:
            if self.words[0] == "*" and self.words[1].upper() == "OK":
                self.isOKInitialResponse = True
            if self.words[1].upper() == "CAPABILITY":
                 self.isCAPABILITYResponse = True                    
            if self.words[1].upper() == "BAD":
                 self.isBAD = True
            printDebug (" self.words[0].upper() =",  self.words[0], "  self.words[1].upper() ",  self.words[1].upper(), debugClass.VV)
          
        if self.wordCount > 3:
            if self.words[2].upper() == "[CAPABILITY" or  (self.words[2] == '[' and self.words[3].upper() == "CAPABILITY"):
                 self.isCAPABILITYResponse = True

            printDebug (" self.words[2].upper() =",  self.words[2].upper(), "  self.words[3].upper() ",  self.words[3].upper(), debugClass.VV)
    
    def update(self):
        self.processAuthMethods()
        MessageWords.update(self)
        self.processResponse()
        
class IMAP4ProxyServerParser(IMAP4Server):
    

        droppedMsg = "_respond message dropped:" 
        def __init__(self):
            self.allow = False
            self.proxyConnection = None
            self.authCheckComplete = False
            self.dataQ = Queue(QSize) #seems like QSize is reasonable for the client to send when there is no auth response
            self.handled = False
            self.drop = False
            self.inProcessList = []
            self._transportwrite = None
            self.user = None
            self.needPassword = False
            self.tag = None
            self.CachedCAPABILITIESResponse = None
            self.authClient = None
            self.serverAuthMethods = ["CLEAR"] # important  default auth method
            self.clientAuthMethods = []
            self.accessLogger = AccessLogger()


        def writeToServer(self,data):
#test
#            print ("writeToServer and sleep 30")
#            import time
#            time.sleep(30)
            if self.proxyConnection.peer.transport is not None:
                self.proxyConnection.peer.transport.write(data)     

            
        def _respond(self, state, tag, message):
            if not state:
                state = " BAD "
            if not tag:
                tag = '*'
            if not message:
                message = ''
            msg = ' '.join((tag, state, message, "\r\n"))
            printDebug("IMAP4ProxyServerParser:_respond  have  msg=", msg,debugClass.vv)
            found, msg =  ReplaceLineInStr("\r\n", "\r\n",True, msg)
            printDebug("IMAP4ProxyServerParser:_respond  look for \r\n in msg found=", found, msg,debugClass.vv)
                
            self.writeToClient(msg)

 
        def getLookupResponse(self, key, dictionary):
            try: msg = dictionary[key]
            except: msg = "BAD command unknown"
            
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


                
        def setConnection(self,connection):
            self.proxyConnection = connection
             
        def setDataToSend(self, data): 
            try:    self.dataQ.put(data,QDontBlock,QTimeoutZero)
            except: return False
            else:   return True
            
        def getDataToSend(self):
            try:    dataToSend = self.dataQ.get(QDontBlock,QTimeoutZero )
            except: return None
            else:   return dataToSend
            
            
        def lineReceived(self, line):
            self.accessLogger.receivedChars= self.accessLogger.receivedChars + len(line)
            if self.needPassword:
                printDebug("IMAP4ProxyServerParser needPassword=",self.needPassword ," lineReceived =", Truncate(line,11),debugClass.VV)
                self.parse_LOGIN( self.tag, "LOGIN", line)
                return
            else:
                IMAP4Server.lineReceived(self,line)
            
            printDebugStr(debugClass.VV, "ProxyIMAP4Server inProcess = %d lineReceived [%s]\nProxyIMAP4Server lineReceived allow is %s" , len(self.inProcessList), Truncate(debugStr(line),11), str(self.allow) )  
            if False == self.allow and len(self.inProcessList) > MaxInProcessListSize:
                if self.proxyConnection != None and self.proxyConnection.transport != None:
                    printDebug("ProxyIMAP4Server connection Killed\n")
                    self.proxyConnection.transport.loseConnection()

        def sendLineToServer(self, line):
            printDebug("IMAP4ProxyServerParser sendLineToServer", line)        
            self.writeToServer( line)
            return
        
              
        def sendQData(self, sendit = True):
            dataToSend = self.getDataToSend()
            if (sendit) and (self.proxyConnection != None) and (dataToSend != None):
                printDebug("IMAP4ProxyServerParser->sendData is passing data to dest server  " , debugStr(dataToSend), debugClass.V)
                try: self.writeToServer(dataToSend)         
                except: pass
            return dataToSend
            
        def sendAllWaitingData(self):
             while self.sendQData() != None: continue
             
        def dumpAllWaitingData(self):
             while self.sendQData(False) != None: continue
             
#-----------------------------             
            
        def locateBestAuthMethod(self):
            '''
            order dependent tests to find an auth method to use.  
            test methods in order of preference.
            serverAuthMethods are from the server's capability response
            must return "" if no auth method is found
            '''
            
            printDebug ("locateBestAuthMethod self.serverAuthMethods = ", self.serverAuthMethods, debugClass.vv)
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
                    
                method = "CLEAR"
                if method in self.serverAuthMethods and method in self.clientAuthMethods:
                    return method
            return ""

     
        def setupAuth(self, tag, user,passwd):

            contextFactory = None
            printDebug("testAuth ", user, ":", "xxxx", debugClass.vvv)
            self.user = user
            printDebug("IMAP4ProxyServerParser.authToServerConfig= ", self.authToServerConfig, debugClass.vv)
            if (self.authClient == None):
                self.authClient =  ProxyIMAP4Client(passwd,contextFactory, self)
                self.authClient.accessLoggerRef = self.accessLogger
                self.authClient.transport = self.proxyConnection.transport
                printDebug("configured Authmethods = ", self.clientAuthMethods, debugClass.vv)
            
                if  InConfig('crammd5', self.authToServerConfig) :
                    #add CRAM-MD5 authenticator
                    cAuth = imapCRAMMD5ClientAuthenticator(user)
                    self.authClient.registerAuthenticator(cAuth)
                    self.clientAuthMethods.append("CRAM-MD5")

                if  InConfig('plain', self.authToServerConfig):
                    #add PLAIN authenticator
                    cAuth = imapPLAINAuthenticator(user)
                    self.authClient.registerAuthenticator(cAuth)
                    self.clientAuthMethods.append("PLAIN")

                if  InConfig('login', self.authToServerConfig):
                    #add LOGIN authenticator
                    cAuth = imapLOGINAuthenticator(user)
                    self.authClient.registerAuthenticator(cAuth)
                    self.clientAuthMethods.append("LOGIN")
                    
                if  InConfig('clear', self.authToServerConfig):
                    #add CLEAR authenticator
                    cAuth = imapCLEARAuthenticator(user)
                    self.authClient.registerAuthenticator(cAuth)
                    self.clientAuthMethods.append("CLEAR")
                
                printDebug("configured Authmethods = ", self.clientAuthMethods, debugClass.vv)
            if (self.authCheckComplete == False):
                authMethodToUse = self.locateBestAuthMethod()
                self.accessLogger.entry['proxy-authmethod'] =  authMethodToUse
                if authMethodToUse == "":
                    self.accessLogger.entry['proxy-authmethod'] =  "unsupported"
                    self.accessLogger.entry['result']=  "Unsupported server authmethod"
                    self.authComplete(0, tag, user, passwd)
                else:
                    self.authClient.authenticateWithMethod( tag, authMethodToUse )

#-----------------------------             

        def authComplete(self, result, tag, user, passwd):
 
            printDebug("ProxyIMAP4Server->authComplete  =" , debugStr(result) , " tag=" ,tag, " user =", user, " passwd =","xxxx" , debugClass.V)
            if result == 0:
                self.result = False
                self.allow =  False
                self.accessLogger.entry['state'] =  AccessLogger.state[3]
                printDebug("ProxyIMAP4Server->authComplete login failed for " , user, debugClass.V)
            else:
                self.result = True
                self.allow =  True
                self.accessLogger.proxyAuthorized = True
                self.accessLogger.entry['state'] =  AccessLogger.state[4]

                printDebug("ProxyIMAP4Server->authComplete login success for " , user, debugClass.V)


            printDebug("authComplete", tag, user, "xxxx", self.result, debugClass.V)
            if (user and self.allow):
                self.setupAuth(tag, user , passwd)
                return result
            else:
                self.dumpAllWaitingData() #empty the data to send
                printDebug("ProxyIMAP4Server->authComplete user not allowed  kill the connection", debugClass.V)
                self.writeToClient(tag + " NO Authentication failed: unauthorized\r\n")         
                if (self.proxyConnection != None and self.proxyConnection.transport != None):               
                   self.proxyConnection.transport.loseConnection()
            return result  


        def do_LOGIN(self, tag, user, passwd):
           if user != None:
                self.accessLogger.entry['user'] =  user
           self.accessLogger.entry['client-authmethod'] =  "IMAP-LOGIN"
           
           try: ipaddressStr = str(self.proxyConnection.transport.getPeer()[1])
           except: passwd == None
           printDebug( "ProxyIMAP4Server->do_LOGIN user=" , user , " passwd=" , "xxxx", " service=IMAP ipaddress=", ipaddressStr, debugClass.V)     
           if user == None or passwd == None:
                self.authComplete(0, tag, user, passwd)
           else:
                maybeDeferred(ProxyHelper.authenticateAndAuthorizeUser, user, passwd, "IMAP", ipaddressStr ).addCallback(self.authComplete,tag, user, passwd) 
                 
                 
        def strip_quotedstring(self, quotedstring):
            '''
            if first and last chars are double quotes, then convert so we can use the original string
            \\ to \ 
            \" to "
            '''
            strippedstring = quotedstring
            pLen = len(quotedstring)
            if pLen > 1:
                if quotedstring[0] == '"' :
                    if quotedstring[-1]  == '"' : #strip \\ and \"
                        strippedstring = quotedstring[1 : -1]
                        strippedstring = strippedstring.replace("\\\"", "\"")
                        strippedstring = strippedstring.replace("\\\\", "\\")
            return strippedstring
            
        def parse_LOGIN(self, tag, cmd, rest):
#   Two flavors of the clear text imap Login command implemented here. The first is standard and defined in RFC 3501
#   S: * OK IMAP4 Server
#   C: 1.29 LOGIN user password\r\n
#   S: 1.29 OK [CAPABILITY IMAP4 etc etc ] Success (no protection)\r\n'
#
#   A clear text imap Login which seems to use a SASL form (handled in the except case below)
#   S: * OK IMAP4 Server
#   C: 1.29 LOGIN user\r\n
#   S: + go ahead\r\n
#   C: password\r\n
#   S: 1.29 OK [CAPABILITY IMAP4 etc etc ] Success (no protection)\r\n'

#a good password test case is where " and \ are actually in the password: everything in the brackets including spaces [\\"t e s t\\"]
           #printDebug( "ProxyIMAP4Server->parse_LOGIN tag=" ,  debugStr(tag) , " cmd=", debugStr(cmd) , " rest=" , debugStr(rest),  debugClass.VV)            
           user = None
           passwd = None
           self.tag = tag
           loginPassword = rest
           try:
                (user, rest) = self.arg_astring(rest)
                user = self.strip_quotedstring(user)
                passwd = self.strip_quotedstring(rest) #rest is the original password form
                if passwd == None or len(rest) == 0: #see if the original password is missing
                    raise
                    
                self.do_LOGIN(tag,user,passwd)                 
                return 
                
           except: 
                if self.user == None and user != None:
                    self.user = user
                    self.writeToClient("+ go ahead\r\n")
                    self.needPassword = True
                    return
                elif self.user != None:
                    passwd = loginPassword 
                    self.needPassword = False
                    self.do_LOGIN(tag,self.user,loginPassword)
                    return 
                    
                self.writeToClient(tag + " NO Authentication failed: unauthorized\r\n")         
                if (self.proxyConnection != None and self.proxyConnection.transport != None):               
                    self.proxyConnection.transport.loseConnection()  
                return
         
        def do_CRAMMD5(self, tag):
            self.writeToClient(tag + " NO Authentication failed: unauthorized\r\n")         
            if (self.proxyConnection != None and self.proxyConnection.transport != None):               
               self.proxyConnection.transport.loseConnection()
            
        def do_AUTHENTICATE(self, tag, authMethod):
            self.writeToClient(tag + " NO Authentication failed: unauthorized\r\n")         
            if (self.proxyConnection != None and self.proxyConnection.transport != None):               
               self.proxyConnection.transport.loseConnection()

 
        def parse_AUTHENTICATE(self, tag, cmd, rest): 
            try:
                (authMethod, rest) = self.arg_astring(rest)
                printDebug( "ProxyIMAP4Server->parse_AUTHENTICATE authMethod=" , authMethod , debugClass.VV)
            except: 
                if (self.proxyConnection != None and self.proxyConnection.transport != None):               
                    self.proxyConnection.transport.loseConnection()
           
                 
            return self.do_AUTHENTICATE(tag,authMethod)
        
        def do_LOGOUT(self, tag, cmd, rest):
             printDebug( "ProxyIMAP4Server->do_LOGOUT cmd=" , cmd ," rest=", rest, debugClass.VV)
             return
             
        def setDataInProcess(self, tag):
            try:    self.inProcessList.append(tag)
            except: return False
            else:   return True
            
             
        def removeTagInList(self, tag):
            if None == tag:
                return False
                            
            try: self.inProcessList.remove(tag)
            except: return False
            return True
             
        def getTag(self, data):
            s = str(data)
            splitData = s.splitlines()
            for aLine in splitData:
                end = aLine.find(" ",0,20)
                if end != -1:
                    firstWord = aLine[0:end]
                    if self.removeTagInList(firstWord):
                        return firstWord
                     
            return None

        def removeDataInProcess(self, data):
            if None == self.getTag(data):
                return False
            return True
        
        def do_CAPABILITY(self, tag, cmd, rest):
            self.setDataInProcess(tag)
            safeMessage = ''.join( [tag," CAPABILITY\r\n"] )
            self.writeToServer(safeMessage)        
            self.dumpAllWaitingData()
            self.handled = True
            
            return

            
        def do_UNSUPPORTED(self, tag, cmd, rest):
            printDebug( "ProxyIMAP4Server->do_UNSUPPORTED " , debugStr(tag) , " " , debugStr(cmd) , " " ,debugStr(rest),  debugClass.VV)
            #self.sendBadResponse(tag, 'Unsupported command')
            return

        def parse_command(self, line):
            #printDebug( "ProxyIMAP4Server->parse_command line=" , debugStr(line),  debugClass.VV )
            if self.authCheckComplete:
                printDebug(  "ProxyIMAP4Server parse_command nothing to do leaving"  , debugClass.VV)
                return
                
            IMAP4Server.parse_command(self, line)
             
            
        def dispatchCommand(self, tag, cmd, rest, uid=None):
            
            #printDebug(  "ProxyIMAP4Server dispatchCommand tag=" , debugStr(tag) ," cmd=" , debugStr(cmd), " rest=" , debugStr(rest)  , debugClass.VV)
            if self.authCheckComplete:
                printDebug(  "ProxyIMAP4Server dispatchCommand nothing to do leaving"  , debugClass.VV)
                return
            
            
            ourCommands = { "LOGIN": "parse_LOGIN",
                            "AUTHENTICATE": "parse_AUTHENTICATE" ,
                            "CAPABILITY" : "do_CAPABILITY"
                           }
            default = 'do_UNSUPPORTED'
            
            action = ourCommands.get(cmd, default)
            printDebug(  "cmd=" , action, debugClass.VV )
            
            if cmd == None:
                 self.sendBadResponse(tag, 'Illegal syntax: Missing command')
                 return    
                 
            if rest == None and cmd != "CAPABILITY" :
                 self.sendBadResponse(tag, 'Illegal syntax: Missing argument')
                 return
                 
            dispatch = getattr(self, action, None)
            if dispatch:
                try:
                    dispatch(tag, cmd, rest)
                except IllegalClientResponse, e:
                    self.sendBadResponse(tag, 'Illegal syntax: ' + str(e))
                except IllegalOperation, e:
                    self.sendNegativeResponse(tag, 'Illegal operation: ' + str(e))
                except IllegalMailboxEncoding, e:
                    self.sendNegativeResponse(tag, 'Illegal mailbox name: ' + str(e))
                except Exception, e:
                    self.sendBadResponse(tag, 'Illegal syntax ')
                    log.err()
                    debugClass.Break()
        
        def processCapabilityMsg(self, inData):
            printDebug ("IMAP4ProxyServerClass->processCapabilityMsg processed:" ,inData, debugClass.VV) 
            
            capabilityMsg = CapabilityMsg(inData)
            outData = capabilityMsg.msg
            capabilityMsg.processResponse()
            foundTag = self.removeDataInProcess(capabilityMsg.msg)  
            
            isCAPABILITYResponse = capabilityMsg.isCAPABILITYResponse
            isOKInitialResponse = capabilityMsg.isOKInitialResponse
            isBAD = capabilityMsg.isBAD
            printDebugStr( debugClass.VV, "foundTag=%s isOKInitialResponse=%s isCAPABILITYResponse=%s",(foundTag),(isOKInitialResponse), (isCAPABILITYResponse))
                
            if isCAPABILITYResponse:
                capabilityMsg.processAuthMethods()
                printDebug ("IMAP4ProxyServerClass->processCapabilityMsg processed:" ,capabilityMsg.msg, debugClass.VV)  
                
                if not isBAD: # Add auth methods that we specifically support in ProxyIMAP4Client when method appears in the mail server's capability response
                    if  not ("CRAM-MD5" in self.serverAuthMethods) and ("AUTH=CRAM-MD5" in capabilityMsg.authMethods):
                        self.serverAuthMethods.append("CRAM-MD5")
                        printDebug ("found CRAM-MD5",debugClass.VV)
                        
                    if  not ("LOGIN" in self.serverAuthMethods) and ("AUTH=LOGIN" in capabilityMsg.authMethods):
                        self.serverAuthMethods.append("LOGIN")
                        printDebug ("found LOGIN",debugClass.VV)
                        
                    if  not ("PLAIN" in self.serverAuthMethods) and ("AUTH=PLAIN" in capabilityMsg.authMethods):
                        self.serverAuthMethods.append("PLAIN")
                        printDebug ("found PLAIN",debugClass.VV)
    
                    if  ("CLEAR" in self.serverAuthMethods) and ("LOGINDISABLED" in capabilityMsg.authMethods):
                        self.serverAuthMethods.remove("CLEAR")
                        printDebug ("found LOGINDISABLED, removed CLEAR",debugClass.VV)

                printDebug(" self.serverAuthMethods = ", self.serverAuthMethods, " capabilityMsg.authMethods = ", capabilityMsg.authMethods, debugClass.VV)
               
                outData = capabilityMsg.msg
                self.CachedCAPABILITIESResponse = outData
                printDebug( "IMAP4ProxyServerClass->processCapabilityMsg out:", (outData) , debugClass.VV)
        
                printDebug( "IMAP4ProxyServerClass->processCapabilityMsg drop other requests  :", (outData) , debugClass.VV)
                self.dumpAllWaitingData()
    
            if isCAPABILITYResponse or isBAD or isOKInitialResponse:
                if isBAD:
                    self.accessLogger.entry['result'] =  "BAD. "
                    
            return outData
           
        def writeToClient(self,inData):
            printDebug ("IMAP4ProxyServerClass->writeToClient inData:", inData , debugClass.VV)
            outData = inData
     
            
            printDebug ("IMAP4ProxyServerClass->writeToClient self.authCheckComplete=", self.authCheckComplete, " outData:", outData , debugClass.VV)
            if not self.authCheckComplete:
                outData = self.processCapabilityMsg(inData)
                printDebug ("IMAP4ProxyServerClass->writeToClient outData:", outData , debugClass.VV)
           
            if None != self._transportwrite:
                self._transportwrite(outData)
                return
                
            printDebug( "IMAP4ProxyServerClass->writeToClient FAILED (_transportwrite == None) out:", debugStr(outData) , debugClass.VV)
           

class IMAPProxyProtocol(Proxy):

    def __init__(self):
        self.peer = None

    def setPeer(self, peer):
        self.peer = peer

    def dataReceived(self, data):
        printDebug("IMAPProxyProtocol:dataReceived=", data, debugClass.VV)
        if self.peer.transport is not None:
            self.peer.transport.write(data)
        
        
        
class IMAPProxy(IMAPProxyProtocol):

    noisy = True
    peer = None
    tlsStarted= False
    canStartTLS = False    
    tlsState = 0
    connectState = 0
    mailClient = None
    proxyClient = None
    cachedConnectMessage = None
    context = None
    mailServerTransport = None
    mailClientTransport = None
    accessLoggerRef = None
    CAPABILITY_REQUEST = "001 CAPABILITY\r\n"
    def setPeer(self, peer):
        self.peer = peer
          
    def connectionLost(self, reason):
        if self.peer is not None:
            if self.peer.transport is not None:
               self.peer.transport.loseConnection()
            self.mailClient = self.peer = None
        elif self.noisy:
            if self.accessLoggerRef is not None:
                printDebug("IMAPProxy: accessLoggerRef['result'] was =", self.accessLoggerRef['result'], " is now= ", str(reason.value), debugClass.V)
                self.accessLoggerRef['result'] =  str(reason.value)
            printDebug("IMAPProxy: Unable to connect with server: %s " % (reason,),debugClass.vvv)
           
    def createContextFactory(self):
        if self.context is not None:
            return self.context
            
        try: from twisted.internet import ssl
        except: return None

        self.context = ssl.ClientContextFactory()
        self.context.method = ssl.SSL.TLSv1_METHOD
        return self.context

    def resumeConnectionToClient(self, connectedMsg):
        if  self.peer.transport != None:
            try:
                self.peer.transport.resumeProducing()
                self.peer.transport.write(connectedMsg) #write to client
            except:
                    reason = protocol.connectionDone
                    reason.value = "BAD. Client connection failed."
                    self.connectionLost(reason)
           
    def dataReceived(self, data):
        printDebug("IMAPProxy:dataReceived write to client state=",self.tlsState," data=", data, debugClass.VV)
        
           
#---------------- starttls with server code       
        printDebug("IMAPProxy:dataReceived state=",self.tlsState," data=", data, debugClass.VV)
        if self.tlsState > 4: #the most common case first
            if (self.peer.imapServer.authClient and False == self.peer.imapServer.authClient.authenticated) : 
                self.peer.imapServer.authClient.lineReceived(data)
            else:
                if self.peer.transport is not None:
                    self.peer.transport.write(data) #write to client
        elif 0 == self.tlsState:  #initialize the connection with the server        
            self.cachedConnectMessage = data
            self.peer.imapServer.processCapabilityMsg(data)  #see if there is a capabilities response attached to the connect message
            if (self.peer.imapServer.CachedCAPABILITIESResponse == None):
                printDebug("IMAPProxy:dataReceived   CachedCAPABILITIESResponse == None, sending CAPABILITY request to server", debugClass.vv)
                self.transport.write(IMAPProxy.CAPABILITY_REQUEST) # test for starttls on the server and get the available auth methods      
                self.tlsState = 1
            else:
                self.tlsState =3 # skip over requesting CAPABILITY response (we have it now) and skip TLS negotitation related states for now
                self.resumeConnectionToClient( self.cachedConnectMessage)
        elif 1 == self.tlsState:  #This should be a CAPABILITY response.
            self.peer.imapServer.processCapabilityMsg(data)     
            self.tlsState =3 # skip over TLS negotiation code for now
            self.resumeConnectionToClient(self.cachedConnectMessage)
        elif 2 == self.tlsState:
            self.createContextFactory()
            from twisted.internet import interfaces
            tls = interfaces.ITLSTransport(self.transport, None)
            printDebug("startTls with self.context=", self.context," tls= ", tls, debugClass.v)
            self.peer.imapServer.accessLogger.entry['server-transport'] =  AccessLogger.transport[2]            
            if self.peer.transport != None:
                try:
                    self.transport.startTLS(self.context)
                    self.tlsStarted = True
                    self.peer.transport.resumeProducing()
                    self.peer.transport.write(self.cachedConnectMessage) #write to client
                    self.tlsState =3
                except Exception,e:
                    if self.peer.imapServer.authClient != None:
                        reason = protocol.connectionDone
                        reason.value = "BAD. Client TLS connection failed."
                        self.peer.imapServer.authClient.connectionLost(reason)
                        
#---------------- end starttls with server code       
        elif 3 == self.tlsState or 4 == self.tlsState:
            printDebug("IMAPProxy:dataReceived state=",self.tlsState," data=", data, debugClass.VV)
            if (self.peer.imapServer.authClient and False == self.peer.imapServer.authClient.authenticated) : 
                self.peer.imapServer.authClient.lineReceived(data)
            else:               
                self.tlsState = 5
                if self.peer.transport is not None:
                    self.peer.transport.write(data) #write to client


class IMAPProxyClient(IMAPProxy):  
    host = "securityproxy_mail"
    
    def connectionMade(self):    
        '''
            self.transport is the connection to the mail server
            self.transport.write 
            self.peer.transport is the connection back to the mail client 
            self.peer.transport.write --> IMAPProxyServerParser.writeToClient
        '''
        # We're connected, everybody can read to their hearts content.
        printDebug("IMAPProxyClient->connectionMade from proxy:", str(self.transport.getHost() ), " to server:", str(self.transport.getPeer()))

        self.peer.setPeer(self)
        self.proxyClient = self.transport
        if self.peer.transport != None:
            try:
                self.peer.transport.resumeProducing()
            except:
                reason = protocol.connectionDone
                reason.value = "Client connection failed (possible SSLv2 attempt)."
                self.connectionLost(reason)
                return
                
        if self.peer != None:
            self.accessLoggerRef = self.peer.imapServer.accessLogger
            self.peer.imapServer.accessLogger.entry['state'] =  AccessLogger.state[3]
           
    def connectionLost(self, reason):
        self.factory.server.imapServer.accessLogger.entry['result'] =  str(reason.value)
        printDebug ("IMAPProxyClient: connection lost reason=", reason.value)
        if self.proxyClient is not None:
            self.proxyClient.loseConnection()                
            IMAPProxy.connectionLost(self, reason)
        
        if self.factory.server is not None:
            if self.factory.server.transport is not None:
                self.factory.server.transport.loseConnection()                
            self.factory.server.connectionLost(reason)
            
         
class IMAPProxyClientFactory(ProxyClientFactory):

    protocol = IMAPProxyClient


    
    
class IMAPProxyServer(IMAPProxy):

    clientProtocolFactory = IMAPProxyClientFactory


    
class IMAP4ProxyServerClass(IMAPProxyServer):

    clientProtocolFactory = IMAPProxyClientFactory
 
    def __init__(self):
        self.imapServer = IMAP4ProxyServerParser()
        self.transportLoseConnection = None
        self.accessLogged = False
        
    def checkMaxConnectionLimit(self):
        numReadFDs = len(reactor._reads)
        #print "checkMaxConnectionLimit PID=%d read FDs=%d MaxFDs=%d ConnectionLimit=%d " % (os.getpid(), numReadFDs , EnvironmentClass.MaxFDs, EnvironmentClass.ConnectionLimit )
        printDebugStr(0, "checkMaxConnectionLimit read FDs=%d MaxFDs=%d ConnectionLimit=%d " ,numReadFDs , EnvironmentClass.MaxFDs, EnvironmentClass.ConnectionLimit )
        if numReadFDs > EnvironmentClass.ConnectionLimit:
            printDebug( "checkMaxConnectionLimit reactor.self._reads =" , numReadFDs, " > ConnectionLimit =", EnvironmentClass.ConnectionLimit)
            self.imapServer.accessLogger.entry['result'] = "Proxy maximum connection limit reached PID(%d) FDs(%d)." % (os.getpid(), numReadFDs)
            ProxyLog.LogErrIMAP( self.imapServer.accessLogger.entry['result'] , " err =", "EMFILE")
            self.transport.loseConnection()
            return True
        return False
        

    def connectionMadeOverride(self):
        #a non-ssl connection to the mail server
        client = self.clientProtocolFactory()
        client.setServer(self)
        self.imapServer.accessLogger.entry['server-transport'] = AccessLogger.transport[0]
        if self.checkMaxConnectionLimit():
            return
            
        self.imapServer.accessLogger.entry['state']=  AccessLogger.state[2]
        reactor.connectTCP(self.factory.host, self.factory.port, client)

    def myLoseConnection(self):
        if False == self.accessLogged:
            self.accessLogged = True
            #PrintThing(self.imapServer.accessLogger)
            keepPreviousResult = True
            if  -1 != self.imapServer.accessLogger.entry['result'].find("BAD", 0 , 5) :  # Result is A generic connection failure. Replace it.
                keepPreviousResult = False
                self.imapServer.accessLogger.entry['result'] = ""
                
            if self.imapServer.accessLogger.entry['client-authmethod'] ==  "": #no valid authenticate from client. expects IMAP-LOGIN
                self.imapServer.accessLogger.entry['result'] = "No valid auth method from client. Verify that client and server are configured for mobile access. " + self.imapServer.accessLogger.entry['result']
                keepPreviousResult = True
                
            prefixStr = ""                
            if self.imapServer.accessLogger.entry['state'] ==  AccessLogger.state[4] and  self.imapServer.accessLogger.receivedChars > 0 and  self.imapServer.accessLogger.serverAuthorized == False:
                prefixStr = "BAD. User not authorized by mail server. "
            elif self.imapServer.accessLogger.entry['state'] ==  AccessLogger.state[2] and  self.imapServer.accessLogger.receivedChars == 0:
                prefixStr = "BAD. Proxy failed connection with mail server. "
            elif self.imapServer.accessLogger.entry['state'] ==  AccessLogger.state[3] and  self.imapServer.accessLogger.proxyAuthorized == False  and  self.imapServer.accessLogger.serverAuthorized == False:
                prefixStr = "BAD. User not authorized by proxy server. "
            elif self.imapServer.accessLogger.receivedChars == 0:
                self.imapServer.accessLogger.entry['state'] =  AccessLogger.state[0]
                prefixStr = "BAD. User failed connection with proxy server. "
            elif self.imapServer.accessLogger.entry['state'] !=  AccessLogger.state[5]:
                prefixStr = "BAD. Lost connection. "
            else:
                prefixStr = "OK. "
            
            previousResult = self.imapServer.accessLogger.entry['result']
            if True == keepPreviousResult:
                self.imapServer.accessLogger.entry['result'] = prefixStr + previousResult.replace(",", "." ) 
            else:
                 self.imapServer.accessLogger.entry['result'] = prefixStr
            ProxyLog.LogAccIMAP(self.imapServer.accessLogger.GetLogEntry())
        self.transportLoseConnection()

    def connectionMade(self):
        IMAPProxyServer.connectionMade(self)
        
        self.transportLoseConnection = self.transport.loseConnection
        self.transport.loseConnection = self.myLoseConnection
        self.imapServer.setConnection(self)       
        self.connectionMadeOverride()       
        printDebug("IMAP4ProxyServerClass->connectionMade from client:", str(self.transport.getPeer()), " to proxy:", str(self.transport.getHost()), "is SSL=" , self.transport.TLS, debugClass.V)
        peer = self.transport.getPeer()
          
        self.imapServer._transportwrite = self.transport.write
        self.transport.write = self.imapServer.writeToClient
        self.imapServer.authToServerConfig = self.factory.auth_to_server
        printDebug("IMAP4ProxyServerClass self.factory.auth_to_server=",self.factory.auth_to_server)
        self.imapServer.accessLogger.entry['client'] =  str(self.transport.getPeer()[1])+":"+ str(self.transport.getPeer()[2])
        self.imapServer.accessLogger.entry['proxy'] =  str(self.transport.getHost()[1])+":"+ str(self.transport.getHost()[2])
        self.imapServer.accessLogger.entry['server'] =  str(self.factory.host) + ":" + str(self.factory.port)
        self.imapServer.accessLogger.entry['state'] =  AccessLogger.state[2]
        self.imapServer.accessLogger.entry['result'] =  "BAD. couldn't connect to server"
        self.imapServer.accessLogger.entry['client-authmethod'] =  ""
        if self.transport.TLS:
            self.imapServer.accessLogger.entry['client-transport'] = AccessLogger.transport[1]
        else:
            self.imapServer.accessLogger.entry['client-transport'] = AccessLogger.transport[0]
        
    def dataReceived(self, data):
        self.imapServer.setDataToSend(data)
        self.imapServer.dataReceived(data)
       
        if self.imapServer.authCheckComplete:
            #printDebug( "IMAP4ProxyServerClass->dataReceived allow=" ,debugStr(self.imapServer.allow) , debugClass.VV)
            if (self.imapServer.allow == True):
                printDebug( "IMAP4ProxyServerClass->dataReceived passing data to dest server:", Truncate(debugStr(data), 11), debugClass.VV)
                self.imapServer.writeToServer(data)
            else:
                self.imapServer.accessLogger.proxyAuthorized = True
                self.imapServer.accessLogger.entry['result'] =  "".join("user:", self.imapServer.accessLogger.entry['user'], ", failed proxy authorization")
                ProxyLog.LogErrIMAP(self.imapServer.accessLogger.entry['result'] )
                printDebug( "IMAP4ProxyServerClass->dataReceived not allowed data not sent:" , Truncate(debugStr(data), 11), debugClass.VV)
 
        else:
            if not self.imapServer.handled:
                printDebug("IMAP4ProxyServerClass->dataReceived auth check not complete waiting to send data:", Truncate(debugStr(data), 11) , debugClass.VV)

    def startedConnecting(self, connector):
        pass
        
class IMAP4SSLProxyServerClass(IMAP4ProxyServerClass):
        
    def connectionMadeOverride(self):

        #an ssl connection to the mail server
        client = self.clientProtocolFactory()
        client.setServer(self)
        self.imapServer.accessLogger.entry['server-transport'] = AccessLogger.transport[1]

        from twisted.internet import reactor
        from twisted.internet import ssl
        printDebug("connectionMadeOverride starting SSL connection to ", str(self.factory.host), " port ", str(self.factory.port) , debugClass.VV)
        contextFactory = ssl.ClientContextFactory()
        printDebug("IMAP4SSLProxyServerClass->connectionMadeOverride host=", str(self.factory.host), " port=", str(self.factory.port), debugClass.VV)
        self.imapServer.accessLogger.entry['state']=  AccessLogger.state[2]
        reactor.connectSSL(self.factory.host, self.factory.port, client, contextFactory)
        printDebug("connectionMadeOverride reactor.connectSSL ", debugStr(client), debugClass.VV)



class IMAPSecurityProxyFactory(ProxyFactory):
   
    def startedConnecting(self, connector):
       pass
        
    def clientConnectionFailed(self, connector, reason):
        printDebug("clientConnectionFailed to ", debugStr(connector), " reason: ", debugStr(reason))
         
    def clientConnectionLost(self, connector, reason):
        printDebug("clientConnectionLost to ", debugStr(connector), " reason: ", debugStr(reason))
