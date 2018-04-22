import subprocess

def lanzaCMD(cmd):
   CREATE_NO_WINDOW = 0x08000000
   try:
       subprocess.check_output(cmd,shell=True,creationflags = CREATE_NO_WINDOW)
   except Exception as e:
	   print e

def creaSrv():
    cmddelsrv = "sc delete backsec-service"
    lanzaCMD(cmddelsrv)
    cmdcreatesrv = 'sc create backsec-service binPath= "C:\\Program Files\\backsec\\backsec-service.exe" start= auto'
    lanzaCMD(cmdcreatesrv)
    cmdsetdesc = 'sc description backsec-service "BackSec Secure Backup Service"'
    lanzaCMD(cmdsetdesc)
    lanzaCMD('sc start backsec-service')
    print "Hecho"
    
def main():
    creaSrv()

if __name__ == "__main__":
    main()

