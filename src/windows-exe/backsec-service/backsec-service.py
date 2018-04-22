import pythoncom
import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import sys
import time
##
from backsec import BackSecClient


class TestService(win32serviceutil.ServiceFramework):
    _svc_name_ = 'backsec-service'
    _svc_display_name_ = 'Backsec Backup Service'

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        self.main()

    def main(self):
        rc = None
        bsc = BackSecClient()
        timetowait = 50
        while rc != win32event.WAIT_OBJECT_0:
            bsc.runBackups()
            bsc.writeLine("[-] Waiting {0} seconds to recheck".format(timetowait), output=None)
            time.sleep(timetowait)
            #rc = win32event.WaitForSingleObject(self.hWaitStop, 365 * 60 * 60 * 1000)
            rc = win32event.WaitForSingleObject(self.hWaitStop, 2)


def main():
    rc = None
    bsc = BackSecClient()
    timetowait = 50
    while rc != win32event.WAIT_OBJECT_0:
        bsc.runBackups()
        bsc.writeLine("[-] Waiting {0} seconds to recheck".format(timetowait), output=None)
        time.sleep(timetowait)
        rc = win32event.WaitForSingleObject(self.hWaitStop, 5)
        #rc = win32event.WaitForSingleObject(self.hWaitStop, 365 * 24 * 60 * 60 * 1000)


if __name__ == '__main__':
    if len(sys.argv) == 3:
        main()
    elif len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(TestService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(TestService)

