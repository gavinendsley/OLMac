#
#  main.py
#
#  Created by gbv on 1/12/08.
#  Copyright (c) 2008-2009 Apple, Inc. All rights reserved.
#

# Notes:
# problem 1> 2008-01-30 12:36:22-0800 [twisted.protocols.portforward.ProxyFactory] Could not accept new connection (EMFILE)
#          appears to loop unthrottled when the host server is unreachable
#
#

#from utilities import debugEnabled

EXTRAS_PATH=''
LOCAL_PROXYHELPER_PATH='/System/Library/PrivateFrameworks/ProxyHelper.framework/Resources'
OBJC_PATH=''

NEWPATHS = [    EXTRAS_PATH, \
                LOCAL_PROXYHELPER_PATH, \
                OBJC_PATH \
           ]

import sys, os
sys.path = sys.path + NEWPATHS
from utilities import printDebug,printDebugStr,debugStr, debugClass, EnvironmentClass
from utilities import utilities
from utilities import ExceptionHelperClass
from utilities import BOOL
from utilities import ProcessClass
from utilities import ProxyLog

from twisted.python import log
ProxyLog.Open("com.apple.securityproxy_mail")
EXIT_ERR = 0
numWorkers = 0

ExceptionHelperClass.Set("Environment error.")


#def InstallReactor():
#    try: 
#        reactor.install()
#    except:
#        raise Exception("Reactor failed to install")
#
#try:
##needs a select module /System/Library/Frameworks/Python.framework/Versions/current/lib/python2.6/lib-dynload/select.so 
##that has been compiled with POLL support or kqueue support
#    from twisted.internet import selectreactor as reactor
#except:   
#    ProxyLog.Info("WARNING:Environment. python selectreactor unavailable. ")   
#InstallReactor()


from twisted.internet import reactor

utilities = utilities()

logStarted = False

from twisted.application import internet, service
PROXY_APPLICATION_NAME = 'Mail Proxy'


from imapProxyClasses import IMAP4ProxyServerClass
from imapProxyClasses import IMAP4SSLProxyServerClass
from imapProxyClasses import IMAPSecurityProxyFactory

from smtpProxyClasses import SMTPProxyServerClass
from smtpProxyClasses import ESMTPProxyFactory

from proxyClasses import AccessLogger
from proxyClasses import PrivateOpenSSLContextFactory

from optparse import OptionParser
from commandLineOptions import commandLineSettings

import config
import copy
import signal
import ProxyHelper


from multiProcessClasses import MultiProcess
sighupcalled = False

def SIGHUPHanddler(signalNum, stackFrame):
    printDebug( "SIGHUPHanddler signal=" , signalNum, " pid=", os.getpid(), " masterPID=", MultiProcess.masterPID , debugClass.v)
    try: 
        if os.getpid() != MultiProcess.masterPID:
            os.kill (MultiProcess.masterPID, signal.SIGHUP)
    except:
        pass
        
    if (numWorkers < 2 and os.getpid() == MultiProcess.masterPID):
        os.kill(-MultiProcess.masterPID,9)
    
    os.kill (os.getpid(), signal.SIGKILL)

def SIGINTHanddler(signalNum, stackFrame):
    printDebug( "SIGINTHanddler signal=" , signalNum, " pid=", os.getpid(), " masterPID=", MultiProcess.masterPID , debugClass.v)
    try: 
        if os.getpid() != MultiProcess.masterPID:
            os.kill (MultiProcess.masterPID, signal.SIGINT)
    except:
        pass
    
    if (numWorkers < 2 and os.getpid() == MultiProcess.masterPID):
       os.kill(-MultiProcess.masterPID,9)
        
    os.kill (os.getpid(), signal.SIGTERM)
        
#def statsReporter():
#    callLater(10, statsReporter)

   
def ProcessServiceOnce (aService, doOnceServices):
     if None == doOnceServices:
        return True
        
     doIt = False
     if aService.has_key('type') and doOnceServices.has_key(aService['type']):
        theType = aService['type']
        if doOnceServices[theType]:
            doIt = True
            doOnceServices[aService['type']] = False
      
     return doIt
     
def ProcessCommandLineSettingsForService(aService, doOnceServices,psettings):
    """ 
        map the command line settings to the service
    """
         
    doIt = ProcessServiceOnce(aService,doOnceServices)
    if "smtp" ==  aService['type'] and doIt:
        aService['dest_address'] = psettings.smtpDestHost
        aService['bind_port'] = psettings.smtpBindPort
        aService['dest_port'] = psettings.smtpDestPort
    if "imap" ==  aService['type'] and doIt:
        aService['dest_address'] = psettings.mailDestHost
        aService['bind_port'] = psettings.mailBindPort
        aService['dest_port'] = psettings.mailDestPort
        
        
     
def SetAppService(aServiceConfig):
    ExceptionHelperClass.Set("Service startup error: ")
    aServiceConfig.service.setName(str(aServiceConfig.type) + str(aServiceConfig.bind_address) + str(aServiceConfig.bind_port))
    aServiceConfig.service.setServiceParent(application)
    aServiceConfig.service.startService()



from twisted.python import usage

class ServerOptions(usage.Options):
    try:
        EnvironmentClass.CheckForRootPrivs()
    except Exception,e :        
        ProxyLog.Err(ExceptionHelperClass.error," ", e)
        if e != None:
            print e
        EXIT_ERR = 1 
        ProxyLog.Info("exiting (result=%d)" % EXIT_ERR)
        sys.exit(EXIT_ERR)
    
try:
    ProxyLog.Info("starting")
    ProcessClass.removePID()
    ProcessClass.writePID()
    
    signal.signal(signal.SIGHUP, SIGHUPHanddler)
    signal.signal(signal.SIGINT, SIGINTHanddler)

    signal.signal(signal.SIGABRT, SIGINTHanddler)
    signal.signal(signal.SIGTERM, SIGINTHanddler)
    signal.signal(signal.SIGTSTP, SIGINTHanddler)


    ExceptionHelperClass.Set("Configuration file format error.")
  
    doMapSettingsOnceServices = { 'imap': True, 'smtp': True} #service types map to command line settings only for the first service in the config file
    prefsMapping =  copy.deepcopy(doMapSettingsOnceServices)
    proxyPrefs = config.Config(None)
    proxyPrefs.Load(None)   
    
    settings = commandLineSettings(proxyPrefs.service, proxyPrefs.debug)   
    OKQuit = False
    parser = OptionParser()
    settings.installOptions(parser)
    optionsResult = settings.parseOptions()
    if False == optionsResult:
        ProxyLog.Err( "commandLineSettings parseOptions failed=" + str(settings))
        raise # sys.exit(1)

    if config.defaultConfigFile.lower() != settings.prefsfile.lower(): 
        #reload prefs based on command line switch to a new file
        initialSettings =  copy.deepcopy(settings)
        proxyPrefs = config.Config(None)
        proxyPrefs.Load(settings.prefsfile)
        settings = commandLineSettings(proxyPrefs.service, proxyPrefs.debug)

    printDebug("sys.path: ", debugClass.V)
    printDebug(sys.path, debugClass.V)
    printDebug(settings, debugClass.V)
    
    logDict = config.Config(proxyPrefs.log)
    ProxyLog.syslogEnabled = logDict.enabled
    ProxyLog.SetAccessTagVersion(logDict.level)
    AccessLogger.version = logDict.level
    
    if debugClass.Enabled():
        if not logStarted:
            log.startLogging(sys.stdout)
            logStarted = True
        debugClass.Break()
        if debugClass.Level() > 0:
             ProxyHelper.proxyHelperDebug(True)
    
           
    if settings.writePrefs:
        writePrefsConfig = config.Config(None)
        writeSettings = commandLineSettings(writePrefsConfig.service, writePrefsConfig.debug)
        writeSettings.installOptions(OptionParser())
        optionsResult = writeSettings.parseOptions()
    
        if False == optionsResult:
            ProxyLog.Err( "writeSettings options Parse failed=" + str(writeSettings))
            raise #sys.exit(1)
    
        for aService in writePrefsConfig.service:
             ProcessCommandLineSettingsForService(aService, prefsMapping,writeSettings)
        writePrefsConfig.Save(writeSettings.prefsfile)
        OKQuit = True
        prefsfilemessage = "Now writing preferences to file: " + writeSettings.prefsfile
        ProxyLog.Info(prefsfilemessage)
        print prefsfilemessage
    #show version and exit.  This should happen last when processing settings.
    infoString = PROXY_APPLICATION_NAME + " (version/%s" % settings.version + " build/" + settings.build + ")"
    ProxyLog.Info(infoString)
    if settings.showVersion:
        print infoString
        OKQuit = True
        
        
    if True == OKQuit:
        sys.exit(0)
        
    
    
    application = service.Application(PROXY_APPLICATION_NAME)  # create the Application 
    serverServices = [] #the array of enabled services we are launching
    
###################
    numWorkers = int(proxyPrefs.num_workers)
    if settings.numWorkers > 0:
        numWorkers = settings.numWorkers
        
    if  numWorkers == 0:
        numProcs = EnvironmentClass.GetNumProcessors()
    else:
        numProcs = numWorkers
   
    EnvironmentClass.NumWorkers = numProcs
    backlog = int(proxyPrefs.listen_backlog)
    if settings.backlog > 0:
        backlog = settings.backlog
    if backlog <= 0:
        backlog = settings.backlog_default #the proxy default
   
    reactor.suggestThreadPoolSize(5 + numProcs)
    serviceList = proxyPrefs.Get("service") # the list of service configurations
    EnvironmentClass.ConnectionBase = len(serviceList) #number of ports reactor is listening on
    for aService in serviceList:
        ProcessCommandLineSettingsForService(aService, doMapSettingsOnceServices,settings)
        aServiceConfig = config.internalConfig(aService) #to access the dict members as attributes
        try:
            aServiceConfig.bind_address = utilities.ValidAddressOrHost(aServiceConfig.bind_address)
            if aServiceConfig.bind_address == "0.0.0.0": #for some reason SSL prefers an empty string
                raise
        except:
                aServiceConfig.bind_address = ""

        if settings.service == "all" or settings.service == "imap":
            if "imap" ==  aServiceConfig.type and BOOL(aServiceConfig.enabled):     
                serverServices.append(aServiceConfig)       
                aServiceConfig.pMailfactory = IMAPSecurityProxyFactory(aServiceConfig.dest_address , int(aServiceConfig.dest_port))
                printDebug("imap destport = ", str(aServiceConfig.dest_port), debugClass.v)
                aServiceConfig.pMailfactory.auth_to_server = aServiceConfig.auth_to_server
                printDebug("imap auth_to_server methods = ", str(aServiceConfig.pMailfactory.auth_to_server), debugClass.v)
    
                if BOOL(aServiceConfig.dest_ssl_enabled):
                    printDebug("imap ssl destination enabled", debugClass.V)
                    aServiceConfig.pMailfactory.protocol = IMAP4SSLProxyServerClass
                else:
                    aServiceConfig.pMailfactory.protocol = IMAP4ProxyServerClass
                if BOOL(aServiceConfig.proxy_ssl_enabled): 
                    printDebug("imap ssl server", debugClass.V)
                    sslContext = PrivateOpenSSLContextFactory(aServiceConfig.ssl_private_key_path, aServiceConfig.ssl_certificate_path)
                    aServiceConfig.service = internet.SSLServer(int(aServiceConfig.bind_port), aServiceConfig.pMailfactory, sslContext, interface=aServiceConfig.bind_address, backlog=backlog)
                else:
                    printDebug("imap", debugClass.V)
                    aServiceConfig.service = internet.TCPServer(int(aServiceConfig.bind_port), aServiceConfig.pMailfactory, interface=aServiceConfig.bind_address, backlog=backlog)
                    
                SetAppService(aServiceConfig)  

            if "smtp" ==  aServiceConfig.type and BOOL(aServiceConfig.enabled):  
                serverServices.append(aServiceConfig)       
                sslContext = PrivateOpenSSLContextFactory(aServiceConfig.ssl_private_key_path, aServiceConfig.ssl_certificate_path)
                aServiceConfig.pSMTPfactory =  ESMTPProxyFactory(aServiceConfig.dest_address ,int(aServiceConfig.dest_port), sslContext)
    
                aServiceConfig.pSMTPfactory.proxy_starttls_enabled = BOOL(aServiceConfig.proxy_starttls_enabled)
                aServiceConfig.pSMTPfactory.proxy_ssl_enabled = BOOL(aServiceConfig.proxy_ssl_enabled)
                aServiceConfig.pSMTPfactory.protocol = SMTPProxyServerClass
                aServiceConfig.pSMTPfactory.auth_to_server = aServiceConfig.auth_to_server
                printDebug("smtp auth_to_server methods = ", str(aServiceConfig.pSMTPfactory.auth_to_server), debugClass.v)
                printDebug("aServiceConfig.pSMTPfactory.proxy_ssl_enabled =", debugStr(aServiceConfig.pSMTPfactory.proxy_ssl_enabled) )            
                printDebug("aServiceConfig.pSMTPfactory.proxy_starttls_enabled =", debugStr(aServiceConfig.pSMTPfactory.proxy_starttls_enabled) )            
               
                printDebug("smtp destport = ", str(aServiceConfig.dest_port), debugClass.v)
                if BOOL(aServiceConfig.proxy_ssl_enabled): 
                    printDebug("smtp ssl server", debugClass.V)
                    sslContext = PrivateOpenSSLContextFactory(aServiceConfig.ssl_private_key_path, aServiceConfig.ssl_certificate_path)                    
                    aServiceConfig.service = internet.SSLServer(int(aServiceConfig.bind_port), aServiceConfig.pSMTPfactory, sslContext, interface=aServiceConfig.bind_address, backlog=backlog)
                else:
                    printDebug("smtp", debugClass.V)
                    aServiceConfig.service = internet.TCPServer(int(aServiceConfig.bind_port), aServiceConfig.pSMTPfactory, interface=aServiceConfig.bind_address, backlog=backlog)
                    
                SetAppService(aServiceConfig)  

    ##  show the services list by type
    for i in range(len(serverServices)):
       if str(serverServices[i].bind_address) == "":
          serverServices[i].bind_address = "all"
       printDebugStr(debugClass.v, "service[%d]=%s dest=%s bindIP=%s bind port=%d dest_port=%d ssl=%s backlog=%d" , i , serverServices[i].type,  str(serverServices[i].dest_address) , str(serverServices[i].bind_address), serverServices[i].bind_port,serverServices[i].dest_port, str(serverServices[i].proxy_ssl_enabled),backlog  )
       if str(serverServices[i].bind_address) == "all":
          serverServices[i].bind_address = ""
            
    ExceptionHelperClass.Set("Program error.")
    EnvironmentClass.SetUID()
    EnvironmentClass.SetRLIMIT()
    ExceptionHelperClass.Set("Reactor running: unknown error")
    MultiProcess.masterPID = os.getpid()
    if numProcs > 1:
        multiProcessProxy = MultiProcess(numProcs)
        multiProcessProxy.run()
    else:
        reactor.run()

except AttributeError, e:            
    ProxyLog.Err("Configuration: ",ExceptionHelperClass.error,' ', e,", check ", config.defaultConfigFile)
    EXIT_ERR = 0  #do not restart the proxy. See launchd plist com.apple.securityproxy_mail.plist
    ProxyLog.Info("status (halted)")


except Exception,e :        
    ProxyLog.Err(ExceptionHelperClass.error, e)
    EXIT_ERR = 1 #restart the proxy. See launchd plist com.apple.securityproxy_mail.plist
    ProxyLog.Info("status (restarting)")
    

finally: 
    
    if EXIT_ERR == 0:
        ProxyLog.Info("exiting (result=%d)"  % EXIT_ERR)
    elif EXIT_ERR == 1:
        ProxyLog.Info("exiting (result=%d)" % EXIT_ERR)
    else: #unhandled exit
        ProxyLog.Info("exiting (result=%d) unknown" % EXIT_ERR)
        os.kill(os.getpid(), 6)
        
    sys.exit(EXIT_ERR)
     


