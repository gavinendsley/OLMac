#
#  multiProcessClasses.py
#
#  Copyright (c) 2008-2009 Apple, Inc. All rights reserved.
#

import os
from utilities import printDebug, debugClass
from utilities import ProxyLog
from utilities import ExceptionHelperClass
import time

from twisted.internet import reactor
from twisted.internet import fdesc
import signal


import warnings
IN_FD=0
OUT_FD=1
ERR_FD=2

class ParentProcess():
    children = {} #dictionary of pids references to children
    masterPID = os.getpid()


    def testing(self):
    
#        import processing, logging
#        logger = processing.getLogger()
#        logger.setLevel(logging.INFO)
#        logger.warning('doomed')


#         from twisted.python import log
#         observer = log.DefaultObserver()
#         setStdout=1         
#         log.startLogging(open('/var/log/foo.log', 'w'), observer)
        pass
        
    def __init__(self):
        self.running = True
        self.testing()
        
    def mapChild(self, pid, child):
        self.children[pid] = child

    def removeChild(self, pid):
        if pid in self.children:
            del self.children[pid]
            
    def addChild(self):
        newChild = ChildProcess()
        pid = os.fork()
        if pid != 0: # parent
            self.mapChild(pid,newChild)
        else: #child
            newChild.run()
         
        return pid
        
    def wait(self):
        try:
            tupleResult = os.wait3(0)
            pid = tupleResult[0]
            theChild = self.children[pid]
            currentTimeSeconds =  time.time()
            printDebug( "currentTimeSeconds=", currentTimeSeconds, " child process startTimeSeconds=", theChild.startTimeSeconds, debugClass.vv)
            uptime = currentTimeSeconds - theChild.startTimeSeconds
            printDebug("os.wait completed with:" , tupleResult, debugClass.vv)
            warnings.warn( "child pid " + str(pid) + " died. wait completed with uptime=" + str(uptime) + " result = " + str (pid) + " need to log this. ")
            del self.children[pid]
            if uptime < 2: #less than 2 seconds between child create and death
                if len(self.children) == 0: #out of children just stop
                    warnings.warn( "no children. need a log message that we are exiting due to some problem")
            else:
                self.addChild()
            return True
        except:
            printDebug ("wait exception", debugClass.v)
            return False
            
    def run(self):
        self.running = True
        ok = True
        while self.running and ok:
            ok = self.wait()
                 
        printDebug ("parent " , os.getpid(), " run done", debugClass.v)
        ProxyLog.Info("parent process done")
        


class ChildProcess():
    running = True
            
    def __init__(self):
        ExceptionHelperClass.Set("Child Process startup error.")
        self.startTimeSeconds = time.time()
        self.pid = 0
        
    def generateNewWakerFDs(self):
        # if the waker uses FDs to wakeup then re-create them after forking.
        
        waker = reactor.waker
        
        if (waker.i == None and waker.o == None):
            return
            
        if (waker.i != None):
            os.close(waker.i)
            
        if (waker.o != None):
            os.close(waker.o)
            
        waker.i, waker.o = os.pipe()
        fdesc.setNonBlocking(waker.i)
        fdesc.setNonBlocking(waker.o)

    def run(self):
        self.generateNewWakerFDs()
        ExceptionHelperClass.Set("Child Process running error.")
        reactor.run()
        pid =os.getpid() 

        printDebug( "child " , pid , " run done", debugClass.vv)
        ProxyLog.Info ("child process done")
        time.sleep(1)
        os.kill(pid,9)   
   
## run method in thread
#  reactor.callInThread(aBlockingMethod, "a single parameter")


# run two methods sequentially in a thread
#commands = [(aBlockingMethodOne, ["Call First"], {})]
#commands.append((aBlockingMethodTwo, ["Call second"], {}))
#threads.callMultipleInThread(commands)
#


# run method in thread and get result as defer.Deferred
#d = threads.deferToThread(doCalculation)
#d.addCallback(printResult)

 
 

    
def KillAll(signalNum, stackFrame):
    global parent
    if parent == 0: 
        return
        
    printDebug ("KillAll signal=" , signalNum, debugClass.v)
    printDebug ("kill all masterpid =", parent.masterPID, debugClass.v)
    ProxyLog.Info("signalled: parent process quitting children and exiting")
    time.sleep(1)
    os.kill(-parent.masterPID,9)
    parent = 0
    
    
    
def setSignals():
    printDebug ("setSignals SIGABRT SIGTERM SIGTSTP", debugClass.vv)
    signal.signal(signal.SIGABRT, KillAll)
    signal.signal(signal.SIGTERM, KillAll)
    signal.signal(signal.SIGTSTP, KillAll)

parent = ParentProcess()

class MultiProcess():

    numProcesses = 0
    running = True
    masterPID = os.getpid()
   
    def __init__(self,numProcesses):
        self.numProcesses = numProcesses
        reactor.suggestThreadPoolSize(5 + numProcesses)
        try:
            os.setpgrp()
        except:
            printDebug ("os.setpgrp not allowed")   
            return
            
    def run(self):

        global parent
        pid = 1
        for numForks in range(self.numProcesses):
            pid = parent.addChild()

        if pid != 0: # parent process
            setSignals()
            masterPID = 0
            parent.run()
            KillAll(0, 0)
             

 #-----------------------------             

    
if __name__ == "__main__":
# testing code
    printDebug ("test")
    multiProcess = MultiProcess(4)
    multiProcess.run()
