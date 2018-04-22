import subprocess,sys,os


def lanzaCMD(cmd):
    CREATE_NO_WINDOW = 0x08000000
    try:
        subprocess.check_output(cmd, shell=True, creationflags=CREATE_NO_WINDOW)
    except Exception as e:
        print e
        file = open("c:\\testing-launch.txt", "a")
        file.write("Error in lanza: {0}\n".format(e))
        file.close()

def main():
    app_path = os.path.dirname(os.path.abspath(sys.argv[0]))
    #
    file = open("c:\\testing-launch.txt", "w")
    cmdres = subprocess.check_output("ping 8.8.8.8",shell=True)
    file.write("CMD res: {0}\n".format(cmdres))
    file.write("The app_path is: {0}\n".format(app_path))
    file.write('The cmd is: "{0}\\backsec.exe" daemon\n'.format(app_path))
    file.close()
    #
    lanzaCMD('"{0}\\backsec.exe" daemon'.format(app_path))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        file = open("c:\\testing-launch.txt", "w")
        file.write("Error in main: {0}\n".format(e))
        file.close()