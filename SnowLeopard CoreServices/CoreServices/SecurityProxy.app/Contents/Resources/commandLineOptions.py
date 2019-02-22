#
#  commandLineOptions.py
#
#  Copyright (c) 2008-2009 Apple, Inc. All rights reserved.
#

from utilities import utilities
from utilities import printDebug
from utilities import debugClass, BOOL
from proxyVersion import PROXY_VERSION_STR, PROXY_BUILD_STR
import config
from utilities import ExceptionHelperClass
exceptionHelper = ExceptionHelperClass()

ErrType = "Command Line Option Err:"
mailPortErr = ": invalid mail port"
smtpPortErr = ": invalid smtp port"
mailDstPortErr = ": invalid mail destination port"
smtpDstPortErr = ": invalid smtp destination port"
IPorHostErr = ": host not found or invalid ip address "
utils = utilities()


class commandLineSettings:
    def __init__(self, serviceList, debugDict):
#        self.demo  = False # False eventually
        self.version = PROXY_VERSION_STR
        self.build = PROXY_BUILD_STR
        self.showVersion = False
        self.debug = False 
        self.debugLevel = 0
        self.mailDestHost ="localhost"
        self.mailBindPort ="143"
        self.mailDestPort ="143"
        self.smtpBindPort = "25"
        self.smtpDestPort = "25"
        self.smtpDestHost ="localhost" 
        
        self.prefsfile = config.defaultConfigFile
        self.writePrefs = False
        self.sslEnabled = False
        self.numWorkers = -1 #< 0 means not set
        self.backlog = -1 #< 0 means not set
        self.backlog_default = 250
        
        if debugDict != None:
            debugDict = config.Config(debugDict)
            self.debug = debugDict.enabled
            self.debugLevel = debugDict.level
        #initialize command line options to the config file settings but take only the first of each type found
        if serviceList != None:
            imapFound = False
            webFound = False
            smtpFound = False
            for aService in serviceList:
                aService = config.Config(aService)
                exceptionHelper.SetAttribute()
                if "imap" ==  aService.type:
                    if False == imapFound:
                        self.mailDestHost = utils.ValidAddressOrHost(aService.dest_address)
                        self.mailBindPort = int(aService.bind_port)
                        self.mailDestPort = int(aService.dest_port)
                        self.sslEnabled = BOOL(aService.proxy_ssl_enabled)
                        imapFound = True
                    else:
                        continue
                if "smtp" == aService.type:
                    if False == smtpFound:
                        self.smtpDestHost = utils.ValidAddressOrHost(aService.dest_address)
                        self.smtpBindPort = int(aService.bind_port)
                        self.smtpDestPort = int(aService.dest_port)
                        self.sslEnabled = BOOL(aService.proxy_ssl_enabled)
                        smtpFound = True
                    else:
                        continue
        exceptionHelper.Reset()                
            
    def installOptions(self, parser):
        "add command line options"
        parser.add_option("-D", "--Debug", dest="debug", action="store_true", default=self.debug, help="debug mode")
        parser.add_option("-d", "--mailhost", dest="mail_dest_host", default=self.mailDestHost,  help="the mail proxy's destination hostname or ip address")
        parser.add_option("-t", "--smtphost", dest="smtp_dest_host", default=self.smtpDestHost,    help="the smtp proxy's destination hostname or ip address")
        parser.add_option("-m", "--mail", dest="mail_port", default=self.mailBindPort,    help="the mail proxy's port is " + str(self.mailBindPort))
        parser.add_option("-r", "--smtp ", dest="smtp_port", default=self.smtpBindPort,    help="the smtp proxy's port is " +  str(self.smtpBindPort))
        
        parser.add_option("-u", "--smtpdest", dest="smtp_dst_port", default=self.smtpDestPort,    help="the smtp proxy's destination port is " +  str(self.smtpDestPort))
        parser.add_option("-n", "--maildest", dest="mail_dst_port", default=self.mailDestPort,    help="the mail proxy's destination port is " +  str(self.mailDestPort))
        parser.add_option("-v", "--version", dest="show_version", action="store_true", default=False,    help="show version and build numbers, and exit")
        parser.add_option("-V", "--level", dest="debug_level", type="int", default=self.debugLevel,    help="the debug verbosity [0, 1, 2]")
        parser.add_option("-p", "--prefsPath", dest="prefs_path", default=self.prefsfile,  help="the preferences path is " + str(self.prefsfile) )
        parser.add_option("-P", "--Prefs", dest="write_prefs",  action="store_true", default=self.writePrefs,  help="export a default preferences file, and exit")
        parser.add_option("-s", "--service", dest="service",  default="all", help="run specified service: imap, smtp, all")
        parser.add_option("-w", "--workers", dest="num_workers",  type="int", default=self.numWorkers,  help="the number of worker processes to run: 0 uses the default setting of 1 per core")
        parser.add_option("-b", "--backlog", dest="listen_backlog",  type="int", default=self.backlog,  help="the size of the listen queue: 0 uses the default setting of " + str(self.backlog_default))
         
        self.parser = parser
        
    def parseOptions(self):
        "parse and store command line options"
        
        try:
            (options, args) = self.parser.parse_args()
        except: 
            return False
            
        parseOptionsDebug = False
        if True == options.debug and (options.debug_level > 0):
            parseOptionsDebug = True

        if parseOptionsDebug:
            print "debug=", options.debug
            print "destMailHost=%s"% options.mail_dest_host
            print "smtpDestHost=%s"% options.smtp_dest_host

            print "mailBindPort=%s"% options.mail_port
            print "smtpBindPort=%s"% options.smtp_port

            print "mailDestPort=%s"% options.mail_dst_port
            print "smtpDestPort=%s"% options.smtp_dst_port

            print "version=%s "% self.version
            print "build=%s"   % self.build
            print "debug verbosity=", options.debug_level
            print "preferences file=", options.prefs_path
            print "write prefs file=", options.write_prefs
            print "service=", options.service
            if 0 == options.num_workers:
                print "num processes=default"
            else:
                print "num processes=",options.num_workers
            print "backlog=", options.listen_backlog
         
        tempIP = utils.ValidAddressOrHost(options.mail_dest_host)
        if False == tempIP:
            print ErrType + IPorHostErr + str(options.mail_dest_host)
            # warn but keep going maybe the DNS is not available
            
        tempSMTPIP = utils.ValidAddressOrHost(options.smtp_dest_host)
        if False == tempSMTPIP:
            print ErrType + IPorHostErr + str(options.smtp_dest_host)
            # warn but keep going maybe the DNS is not available
            
        tempPort = utils.ValidPort(options.mail_port)
        if False == tempPort:
            print ErrType + mailPortErr
            return False
            
        tempPort = utils.ValidPort(options.smtp_port)
        if False == tempPort:
            print ErrType + smtpPortErr
            return False

        tempPort = utils.ValidPort(options.mail_dst_port)
        if False == tempPort:
            print ErrType + mailDstPortErr
            return False
            
        tempPort = utils.ValidPort(options.smtp_dst_port)
        if False == tempPort:
            print ErrType + smtpDstPortErr
            return False

             
        if options.debug_level > debugClass.max:
            options.debug_level = debugClass.max
        if options.debug_level < 0:
            options.debug_level = 0
            
        self.debug = options.debug == True
        self.debugLevel = options.debug_level
        self.mailDestHost = tempIP
        self.smtpDestHost = tempSMTPIP
        self.mailBindPort = int(options.mail_port)
        self.smtpBindPort = int(options.smtp_port)
        
        self.smtpDestPort = int(options.smtp_dst_port)
        self.mailDestPort = int(options.mail_dst_port)

        self.showVersion = options.show_version
        self.prefsfile = options.prefs_path
        self.writePrefs = options.write_prefs
        self.service = options.service
        
        self.numWorkers = options.num_workers
        self.backlog = options.listen_backlog
  
        debugClass.SetEnabled(self.debug)
        debugClass.SetLevel(self.debugLevel)

        printDebug(self,debugClass.V)
       
        return True
        
        
