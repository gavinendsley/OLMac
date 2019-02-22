#!/usr/bin/python
#
#  SetConfig.py
#
#  Copyright (c) 2008-2009 Apple, Inc. All rights reserved.
#

from config import ConfigurationError
from config import Config

class commandLineSettings:
    configPath ="/Library/Preferences/com.apple.securityproxy_mail.plist"
    list = False
    tag = ""
    value = ""
    debug = False
    parser = None
    service = "all"
    result = False
    
    def installOptions(self, parser):
        "add command line options"
        parser.add_option("-l", "--list", dest="list", action="store_true",  help="list tags")
        parser.add_option("-t", "--tag", dest="tag", default=self.tag,  help="the tag to set")
        parser.add_option("-v", "--value", dest="value", default=self.value,    help="the value to set")
        parser.add_option("-s", "--service", dest="service", default=self.service,    help="a specific service type to set")
        parser.add_option("-p", "--path", dest="configPath",default=self.configPath,    help="the config file path to edit")
        parser.add_option("-r", "--result", dest="result",action="store_true",    help="show the resulting config file ")
        
        parser.add_option("-d", "--debug", dest="debug", action="store_true",    help="enable debug mode")
        self.parser = parser
        
    def parseOptions(self):
        "parse and store command line options"
        
        try:
            (options, args) = self.parser.parse_args()
        except: 
            return False
            
        parseOptionsDebug = False
        if True == options.debug:
            parseOptionsDebug = True

        self.debug = options.debug
        self.tag = options.tag
        self.value = options.value
        self.list = options.list
        self.service = options.service
        self.result = options.result
        
        if ( self.tag == "" and self.value != "" ) :
            print "missing tag. exiting"
            return False
        if (self.tag != "" and self.value == "") :
            print "missing value. exiting"
            return False
                        
        if (self.tag == "" and self.value == "") :
            if self.result: # avoid error message
                return False
                
            print "missing tag and value. exiting"
            return False
        
       
        return True
        
if __name__ == "__main__":
# testing code

   
    import os
    import sys
    from optparse import OptionParser
    
    result = 0;
    settings = commandLineSettings()   
    OKQuit = False
    parser = OptionParser()
    settings.installOptions(parser)
    optionsResult = settings.parseOptions()

    try: 
        prefsConfig = Config(None)
        prefsConfig.Load(settings.configPath)
    except ConfigurationError, e: print("\n<Error>: " + str(e)); result = e
    
    if settings.list:
        print "--------------  Settings List -----------------"
        aService = prefsConfig.Get("service.0")
        for index, aField in enumerate(aService):
            if aField == "auth_to_server":
                aService = prefsConfig.Get("service.0.auth_to_server")
                for index, aField in enumerate(aService):
                    print ("auth_to_server." + aField)
            else:
                print (aField)
 
      
    if False == settings.result:
        if False == optionsResult:
            sys.exit(1)
    
    if True == optionsResult:
        for index, aService in enumerate(prefsConfig.Get("service")):
     
            servicetype = ""
            service = settings.service
            try: 
                 servicetype = prefsConfig.Get("service."+ str(index) +".type")
                 bind_port = prefsConfig.Get("service."+ str(index) +".bind_port")
                 if settings.debug:
                    print "ok: get " + servicetype + " " + str(bind_port)
            except ConfigurationError, e: print("\n<Error>: " + str(e)); result = e
            if (servicetype == service or service == "all"):
                try: 
                    prefsConfig.Set("service."+ str(index) + "." + settings.tag,  settings.value); 
                    if settings.debug:
                        print "ok: set "+ settings.tag + " " + str(prefsConfig.Get("service." + str(index)+ "." + settings.tag))
                except ConfigurationError, e: print("\n<Error>: " + str(e)); result = e
        
        
        print "--------------  saving config -----------------"
        prefsConfig.Save(settings.configPath)
        
    if True == settings.result:
        print "file: " + settings.configPath
        os.system ("cat " + settings.configPath)
        
    exitVal = 0
    if result != 0: #an error occured
        exitVal = 1
    sys.exit(exitVal)
