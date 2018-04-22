import os
import stat
import hashlib
import ConfigParser
import sqlite3
import shutil
import time
import datetime
import gzip
import json
import sys
import time
import datetime
import threading
import argparse
# RSA
from Crypto.PublicKey import RSA
# AES
from hashlib import md5
from Crypto.Cipher import AES
from Crypto import Random
# Logs 
import logging
# NOT USED NOW
# import base64
# import codecs
# import binascii

#VSS windows
if os.name == "nt":
    #vss
    import win32com.client
    import ctypes

class BackSecClient:
    '''
    config = {
        'crypt': True, -> Cifrado si o no
        'type' : 'local', -> tipo puede ser: local, direct, reverse
        'compresion': True, -> Gzip compresion si o no
    }
    '''

    config = {
        'crypt': True,
        'type': 'local',
        'compresion': True,
        'passwd': '',
    }

    paths = []  # paths a respaldar
    privatekey = ""
    publickey = ""
    logger = None

    def __init__(self, config={}, paths=[]):
        if config == {} or paths == []:
            self.loadConfig()
        else:
            self.config = config
            self.paths = paths

    def loadConfig(self):
        config = ConfigParser.ConfigParser()
        try:
            app_path = self.pathParser(os.path.dirname(os.path.abspath(__file__)))
        except NameError:  # We are the main py2exe script, not a module
            app_path = self.pathParser(os.path.dirname(os.path.abspath(sys.argv[0])))
        if not os.path.exists('{0}client.conf'.format(app_path)):
            app_path = self.pathParser(os.path.dirname(os.path.abspath(sys.argv[0])))
        config.read('{0}client.conf'.format(app_path))
        try:
            self.config['type'] = str(config.get('GENERAL', 'type'))
            if self.config['type'] == "local":
                self.paths = str(config.get('GENERAL', 'paths')).split(",")
                self.config['crypt'] = eval(config.get('GENERAL', 'crypt'))
                self.config['destination'] = config.get('GENERAL', 'destination')
                self.config['compresion'] = eval(config.get('GENERAL', 'compresion'))
                self.config['logs'] = eval(config.get('GENERAL', 'logs'))
                self.setInitialConfig()
                if self.config['crypt']:
                    self.config['passwd'] = config.get('GENERAL', 'passwd')
                    self.generateKeys()
                    self.loadKeys()
                self.config['full'] = str(config.get('POLICY', 'full'))
                self.config['full'] = self.config['full'].split(",")
                self.config['incremental'] = str(config.get('POLICY', 'incremental'))
                self.config['incremental'] = self.config['incremental'].split(",")
                if self.config['logs']:
                    self.setLogsOn(app_path)
        except Exception as e:
            sys.stdout.write("[!] An error happened loading the configuration\n")
            sys.stdout.write(str(e))

    def setLogsOn(self, app_path):
        logging.basicConfig(filename='{0}backsec-log.log'.format(app_path),
                            format='%(asctime)s,%(msecs)d-%(name)s-%(levelname)s %(message)s',
                            datefmt='%H:%M:%S_%d-%m-%Y',
                            level=logging.DEBUG)
        self.logger = logging.getLogger('backsec')
        self.logger.setLevel(logging.DEBUG)

    def writeLine(self, texto, logtype="info", output="std"):
        texto1 = texto
        if texto[len(texto) - 1] != "\n":
            texto1 = texto + "\n"
        if output == "err":
            sys.stderr.write(texto1)
        elif output==None:
            pass
        else:
            sys.stdout.write(texto1)
        if self.config['logs']:
            if self.logger == None:
                try:
                    app_path = self.pathParser(os.path.dirname(
                        os.path.abspath(__file__)))
                except NameError:  # We are the main py2exe script, not a module
                    app_path = self.pathParser(os.path.dirname(
                        os.path.abspath(sys.argv[0])))
                if not os.path.exists('{0}client.conf'.format(app_path)):
                    app_path = self.pathParser(os.path.dirname(os.path.abspath(sys.argv[0])))
                self.setLogsOn(app_path)
            if logtype == "warn":
                self.logger.warning(texto)
            elif logtype == "error":
                self.logger.error(texto)
            elif logtype == "crit":
                self.logger.critical(texto)
            elif logtype == "debug":
                self.logger.debug(texto)
            else:
                self.logger.info(texto)

    def md5(self, fname):
        try:
            hash_md5 = hashlib.md5()
            with open(fname, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return "No-md5"

    def getFileInfo(self, filename, osname="linux"):
        try:
            fileinfo = os.stat(filename)
            if osname == "linux":
                modtime = fileinfo.st_mtime
            elif osname == "windows":
                modtime = 0
            return {
                'fsze': fileinfo.st_size,
                # 'accesstime': fileinfo.st_atime, 
                # 'creationtime': fileinfo.st_ctime, 
                'mtime': modtime,
                'uid': fileinfo.st_uid,
                'gid': fileinfo.st_gid,
                'mode': fileinfo.st_mode,
            }
        except Exception as e:
            # print e
            return {
                'fsze': 0,
                # 'accesstime': 0, 
                # 'creationtime': 0, 
                'mtime': 0,
                'uid': 0,
                'gid': 0,
                'mode': 0,
            }

    def getFileList(self, path=""):
        filetree = []
        filetree.append({"ori-path": path})
        ext = ""
        self.writeLine("[-] Searching on {0}".format(path))
        lastdirpath = ""
        for dirpath, dirname, files in os.walk(path):
            for directorio in dirname:
                atributes = self.getFileInfo(dirpath)
                atributes['type'] = "d"  # directory
                filetree.append({'path': self.pathParser(dirpath) + \
                                         directorio, 'attr': atributes})
            for filea in files:
                if dirpath != lastdirpath:
                    atributes = self.getFileInfo(dirpath)
                    atributes['type'] = "d"  # directory
                    filetree.append({'path': dirpath, 'attr': atributes})
                if filea.endswith(ext):
                    filenpath = os.path.join(dirpath, filea)
                    fileinfo = self.getFileInfo(filenpath)
                    fileinfo['type'] = "f"  # file
                    filetree.append({'path': os.path.join(
                        self.pathParser(dirpath), filea), 'attr': fileinfo})
                    lastdirpath = dirpath
        return filetree

    def getFileListAllPaths(self):
        filetree = []
        for path in self.paths:
            tmpresult = self.getFileList(path)
            for fileres in tmpresult:
                filetree.append(fileres)
        return filetree

    def pathParser(self, path, endp=True):
        path = path.replace("\\c:\\", "\\")
        if ("\\" in path) or os.name == "nt":
            path = path.replace("/", "\\")
            if not endp or path.endswith("\\"):
                return path
            else:
                return path + "\\"
        if "/" in path:
            path = path.replace("\\", "/")
            if not endp or path.endswith("/"):
                return path
            else:
                return path + "/"

    def getLastDir(self, path):
        lastdir = ""
        arraytmp = []
        if "\\" in path:
            arraytmp = path.split("\\")
        elif "/" in path:
            arraytmp = path.split("/")
        for directory in arraytmp:
            if directory == "":
                arraytmp.remove("")
        lastdir = arraytmp[len(arraytmp) - 1]
        return lastdir

    def setInitialConfig(self):
        self.config['destination'] = self.pathParser(self.config['destination'])
        if self.config['type'] == "local":
            self.config['localdb'] = self.pathParser(self.config['destination'] + "local.db",endp=False)
        if not os.path.exists(self.config['destination']):
            try:
                os.makedirs(self.config['destination'])
            except:
                sys.stderr.write("The application cannot create the directory " + self.config['destination'])
        if not os.path.exists(self.config['localdb']):
            shutil.copy("localtpl.sql", self.config['localdb'])

    def loadKeys(self):
        if os.path.exists("privatekey.pem") and os.path.exists("publickey.pem"):
            fpriv = open("privatekey.pem", 'r')
            fpub = open("publickey.pem", 'r')
            self.privatekey = fpriv.read()
            self.publickey = fpub.read()
            fpriv.close()
            fpub.close()
        else:
            self.writeLine("[!] An error happened charging the keys")

    def loadIndexFile(self, indexpath):
        try:
            f = gzip.open(indexpath, 'rb')
            data = f.read()
            f.close()
            data = data.replace("\\","\\\\")
            return json.loads(data)
        # except ValueError as error:
        except OSError as error:
            # except Exception as error:
            self.writeLine("[!] couldn't load index file '{0}'".format(indexpath),
                           logtype="error")
            return []

    def writeIndexFile(self, indexfile, indexcontent):
        try:
            indexcontent = str(indexcontent)
            indexcontent = indexcontent.replace(", u\"", ", \"")
            indexcontent = indexcontent.replace("{u\"", "{\"")
            indexcontent = indexcontent.replace(": u\"", ": \"")
            indexcontent = indexcontent.replace("L, \"gid\"", ", \"gid\"")
            indexcontent = indexcontent.replace("\\\\", "\\")
            findex = gzip.open(indexfile, 'wb')
            findex.write(indexcontent)
            findex.close()
            return True
        except:
            return False

    # compara el indice anterior con el nuevo (solo para indices nuevos)
    def compareLastIndex(self, lastindex, actualindex, islastafile=True, isactualafile=True):
        res = []
        if islastafile:
            lastindexarr = self.loadIndexFile(lastindex)
        else:
            lastindexarr = lastindex
        if isactualafile:
            actualindexarr = self.loadIndexFile(actualindex)
        else:
            actualindexarr = actualindex
        for indexolditem in lastindexarr:
            if indexolditem.keys()[0] != "ori-path" and indexolditem.keys()[0] == "path":
                found = False
                for i in actualindexarr:
                    if i.keys()[0] != "ori-path" and i['path'] == indexolditem['path']:
                        found = True
                        if indexolditem.keys()[1] == "attr" and i['attr'] != indexolditem['attr']:
                            # print indexolditem['path']
                            res.append(i)
                if not found:
                    deleted = indexolditem
                    deleted['attr'] = {"status": "del"}
                    res.append(deleted)
        # add ficheros nuevos
        for indexnewitem in actualindexarr:
            if indexnewitem.keys()[0] != "ori-path" and indexnewitem.keys()[0] == "path":
                found = False
                for i in lastindexarr:
                    if i.keys()[0] != "ori-path" and i['path'] == indexnewitem['path']:
                        found = True
                if not found:
                    res.append(indexnewitem)
        # fin
        return res
        # Se lee la ruta original del lastindexarr y de actualindexarr y
        # se comprueba si existe cada path ahora, si no existe, se guarda una
        # anotacion como que se ha eliminado, se coprueba entre un index y otro 
        # si varia el mode, el size o el usuario/grupo y mode(permisos)
        # Retorna el index del incremental

    def compareLastIndexRestore(self, lastindexes, actualindex, islindexarray=True):
        res = []
        if islindexarray == False:
            lastindexes = [lastindexes]
        actualindexarr = self.loadIndexFile(actualindex)
        for item in actualindexarr:
            found = False
            for i in res:
                if i['path'] == item['path']:
                    found = True
            if item.keys()[0] != 'ori-path' and not found:
                ifrom = actualindex.replace("/index.gz", "/files")
                ifrom = ifrom.replace("\index.gz", "\\files")
                item['from'] = ifrom
                res.append(item)
        for lastindex in lastindexes:
            lastindexarr = self.loadIndexFile(lastindex)
            for item in lastindexarr:
                if 'ori-path' not in item.keys():
                    found = False
                    for i in res:
                        if i['path'] == item['path']:
                            found = True
                    if not found:
                        ifrom = lastindex.replace("/index.gz", "/files")
                        ifrom = ifrom.replace("\index.gz", "\\files")
                        item['from'] = ifrom
                        res.append(item)
        return res

    def generateKeys(self):
        if not os.path.exists("privatekey.pem") or not os.path.exists("publickey.pem"):
            new_key = RSA.generate(4096)  # generate  RSA key that 4096 bits long
            # Export the Key in PEM format, the PEM extension contains ASCII encoding
            public_key = new_key.publickey().exportKey("PEM")
            private_key = new_key.exportKey("PEM")
            try:
                fprivkey = open("privatekey.pem", 'w')
                fpubkey = open("publickey.pem", 'w')
                fpubkey.write(public_key)
                fprivkey.write(private_key)
            finally:
                fpubkey.close()
                fprivkey.close()
                self.writeLine(public_key, logtype="info", output="std")
                self.writeLine(private_key, logtype="info", output="std")
        else:
            self.writeLine("[-] The keys exists")

    def encryptRSA(self, text, publickey):
        encryptor = RSA.importKey(publickey)
        global encriptedData
        # b64 = codecs.encode(binascii.b2a_base64(text),"base64")
        # encriptedData=encryptor.encrypt(b64[0:len(b64)-1], 0)
        encriptedData = encryptor.encrypt(text, 0)
        return encriptedData[0]

    def decryptRSA(self, text, privatekey):
        decryptor = RSA.importKey(privatekey)
        # dec = base64.b64decode( decryptor.decrypt(text) + "==" )
        dec = decryptor.decrypt(text)
        return dec

    def encryptAES256(self, in_file, out_file, password, key_length=32):
        bs = AES.block_size
        salt = Random.new().read(bs - len('Salted__'))
        key, iv = self.derive_key_and_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        out_file.write('Salted__' + salt)
        finished = False
        while not finished:
            chunk = in_file.read(1024 * bs)
            if len(chunk) == 0 or len(chunk) % bs != 0:
                padding_length = (bs - len(chunk) % bs) or bs
                chunk += padding_length * chr(padding_length)
                finished = True
            out_file.write(cipher.encrypt(chunk))

    def decryptAES256(self, in_file, out_file, password, key_length=32):
        bs = AES.block_size
        salt = in_file.read(bs)[len('Salted__'):]
        key, iv = self.derive_key_and_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        next_chunk = ''
        finished = False
        while not finished:
            chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
            if len(next_chunk) == 0:
                padding_length = ord(chunk[-1])
                chunk = chunk[:-padding_length]
                finished = True
            out_file.write(chunk)

    def derive_key_and_iv(self, password, salt, key_length, iv_length):
        d = d_i = ''
        while len(d) < key_length + iv_length:
            d_i = md5(d_i + password + salt).digest()
            d += d_i
        return d[:key_length], d[key_length:key_length + iv_length]

    def copyFileGzip(self, source, destination):
        fsource = open(source, "rb")
        if self.config['compresion']:
            fdest = gzip.open(destination, 'wb')
        else:
            fdest = open(destination, 'wb')
        try:
            if self.config['crypt']:
                self.encryptAES256(fsource, fdest, self.config['passwd'])
            else:
                byte = "128"
                while byte != "":
                    byte = fsource.read(128)
                    fdest.write(byte)
        finally:
            fsource.close()
            fdest.close()

    def restoreFileGzip(self, source, destination):
        fdest = open(destination, "wb")
        if self.config['compresion']:
            fsource = gzip.open(source, 'rb')
        else:
            fsource = open(source, 'rb')
        try:
            if self.config['crypt']:
                self.decryptAES256(fsource, fdest, self.config['passwd'])
            else:
                byte = "128"
                while byte != "":
                    byte = fsource.read(128)
                    fdest.write(byte)
        finally:
            fsource.close()
            fdest.close()

    def vssDelete(self,id):
        wcd = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        wmi = wcd.ConnectServer(".", "root\cimv2")
        obj = wmi.ExecQuery(
            'SELECT * FROM Win32_ShadowCopy WHERE ID="{0}"'.format(id)
        )
        obj[0].Delete_()

    def findVSS(self,id=""):
        wcd = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        wmi = wcd.ConnectServer(".", "root\cimv2")
        if id != "":
            obj = wmi.ExecQuery("SELECT * FROM win32_ShadowCopy WHERE id='{0}'".format(id))
            return [x.DeviceObject for x in obj]
        else:
            return []

    def getVssList(self):
        res = []
        if os.name == "nt":
            wcd=win32com.client.Dispatch("WbemScripting.SWbemLocator")
            wmi=wcd.ConnectServer(".","root\cimv2")
            obj=wmi.ExecQuery("SELECT * FROM win32_ShadowCopy")
            res = [x.DeviceObject for x in obj]
        return res

    def vssCreate(self,unidad="c:\\"):
        if os.name == "nt":
            wmi=win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2:Win32_ShadowCopy")
            createmethod = wmi.Methods_("Create")
            createparams = createmethod.InParameters
            createparams.Properties_[1].value=unidad
            results = wmi.ExecMethod_("Create",createparams)
            return results.Properties_[1].value
        return []

    def createLink(self, link, destino): #hacer mklink
        flags = {'directory':1,'file':0}
        ##res = ctypes.windll.kernel32.CreateSymbolicLinkW(link, destino, flags['directory'])
        ##return res
        csl = ctypes.windll.kernel32.CreateSymbolicLinkW
        csl.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32)
        csl.restype = ctypes.c_ubyte
        res = csl(link, destino, flags['directory'])
        #csl("c:\\shadow_C", "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy5\\", 1)
        return res

    def doVss(self,path):
        res = [path, []]
        if os.name == "nt":
            shadowlink = "shadow{0}".format(int( time.time() ))
            volunit = path[0:3]
            shadowlinkpath = "{0}{1}".format(volunit,shadowlink)
            vssid = self.vssCreate(volunit)
            self.createLink(shadowlinkpath,"{0}\\".format(self.findVSS(id=vssid)[0]))
            newpath = "{0}{1}{2}".format(volunit,shadowlink,path.replace(volunit,"\\"))
            res = [newpath,[vssid,shadowlinkpath]]
        return res

    def removeVssAndUmount(self,vssid,mountpoint):
        if os.name == "nt":
            os.rmdir(mountpoint)
            self.vssDelete(vssid)

    def doFullBackup(self):
        for path in self.paths:
            vssres = self.doVss(path)
            timestamp = int(time.time())
            query = "INSERT INTO backups VALUES(null," + str(timestamp) + \
                    ",'full','" + path + "','started')"
            dbres = self.setDataToDB(self.config['localdb'], query)
            if dbres:
                self.writeLine("[-] Full backup '{0}' started".format(path))
            else:
                self.writeLine("[-] Full backup '{0}' Failed".format(path),
                               logtype="error")
                continue
            if path == "/":
                lastdir = self.getLastDir("/_ROOT_DIR_") + "/full_" + str(timestamp)
            else:
                lastdir = self.getLastDir(path) + "/full_" + str(timestamp)
            tmpdestination = self.pathParser(self.config['destination'] + lastdir)
            os.makedirs(tmpdestination + "files")
            bckindex = self.getFileList(path)
            self.writeIndexFile(tmpdestination + "index.gz", str(bckindex).replace("'", "\""))
            for item in bckindex:
                try:
                    if item['path'] != "":  # Comprobamos que no es ori-path
                        destpath = item['path'].replace(path, tmpdestination + "files/")
                        destpath = self.pathParser(destpath, endp=False)
                        # Cambiamos path el path del VSS
                        item['path'] = item['path'].replace(path,vssres[0])
                        # Si es Directorio lo crea en destino
                        if item['attr']['type'] == 'd':
                            try:
                                os.makedirs(destpath)
                            except OSError:
                                self.writeLine("\t[!] {0}".format(e),
                                               logtype="error")
                        else:
                            # Si es fichero copia el fichero con gzip:
                            try:
                                self.copyFileGzip(item['path'], destpath)
                            except Exception as e:
                                self.writeLine("\t[!] {0}".format(e),
                                               logtype="error")
                except KeyError as e:
                    self.writeLine("\t[!] {0}".format(e),
                                   logtype="error")
            query = "UPDATE backups set status='completed' where datetime=" + \
                    str(timestamp) + " and type='full' and path='" + path + "'" + \
                    " and status='started'"
            dbres = self.setDataToDB(self.config['localdb'], query)
            if dbres:
                self.writeLine("[-] Full backup '{0}' Completed".format(path))
            else:
                self.writeLine("[-] Full backup '{0}' Failed".format(path))
                continue
        if len(vssres[1]) > 0:
            self.removeVssAndUmount(vssres[1][0], vssres[1][1])

    def doIncrementalBackup(self):
        for path in self.paths:
            vssres = self.doVss(path)
            timestamp = int(time.time())
            query = "INSERT INTO backups VALUES(null," + str(timestamp) + \
                    ",'incremental','" + path + "','started')"
            dbres = self.setDataToDB(self.config['localdb'], query)
            if dbres:
                self.writeLine("[-] Incremental backup '{0}' started".format(path))
            else:
                self.writeLine("[-] Incremental backup '{0}' Failed".format(path))
                continue
            if path == "/":
                lastdir = self.getLastDir("/_ROOT_DIR_") + "/incremental_" + str(timestamp)
            else:
                lastdir = self.getLastDir(path) + "/incremental_" + str(timestamp)
            tmpdestination = self.pathParser(self.config['destination'] + lastdir)
            os.makedirs(tmpdestination + "files")
            # Get last full backup index
            backups = self.getBackups(path, bcktype='full')
            lastfulldir = self.getLastDir(path) + "/full_" + str(backups[len(backups) - 1][1]) + "/"
            lastindex = self.config['destination'] + "/" + lastfulldir + "index.gz"
            # fin
            tmpindex = self.getFileList(path)
            bckindex = self.compareLastIndex(lastindex, tmpindex, isactualafile=False)
            self.writeIndexFile(tmpdestination + "index.gz", str(bckindex).replace("'", "\""))
            for item in bckindex:
                try:
                    if item['path'] != "":  # Comprobamos que no es ori-path
                        destpath = item['path'].replace(path, tmpdestination + "files/")
                        destpath = self.pathParser(destpath, endp=False)
                        # Cambiamos path el path del VSS
                        item['path'] = item['path'].replace(path, vssres[0])
                        # Si es Directorio lo crea en destino
                        if item['attr']['type'] == 'd':
                            try:
                                os.makedirs(destpath)
                            except OSError as e:
                                self.writeLine("\t[!] {0}".format(e),
                                               logtype="error")
                        else:
                            # Si es fichero copia el fichero con gzip:
                            try:
                                self.copyFileGzip(item['path'], destpath)
                            except Exception as e:
                                err = "\t[!] " + str(e)
                                self.writeLine(err, logtype="error")
                except KeyError as e:
                    self.writeLine("\t[!] {0}".format(e),
                                   logtype="error")
            query = "UPDATE backups set status='completed' where datetime=" + \
                    str(timestamp) + " and type='full' and path='" + path + "'" + \
                    " and status='started'"
            dbres = self.setDataToDB(self.config['localdb'], query)
            if dbres:
                self.writeLine("[-] Incremental backup '{0}' Completed".format(path))
            else:
                self.writeLine("[-] Incremental backup '{0}' Failed".format(path))
                continue
        if len(vssres[1]) > 0:
            self.removeVssAndUmount(vssres[1][0], vssres[1][1])

    def restoreFull(self, backupidarr, pathdest, pathsource="/"):
        for backupid in backupidarr:
            query = "SELECT * FROM backups WHERE id={0}".format(backupid)
            dbres = self.getDataFromDB(self.config['localdb'], query)
            timestamp = dbres[0][1]
            path = dbres[0][3]
            if dbres != []:
                self.writeLine("[-] Full backup '{0}' restoring on {1} started\n".format(path, pathdest))
            else:
                self.writeLine("[-] Full backup restore '{0}' Failed\n".format(path))
                continue
            if path == "/" or path == "c:\\":
                lastdir = self.getLastDir("/_ROOT_DIR_") + "/full_" + str(timestamp)
            else:
                lastdir = self.getLastDir(path) + "/full_" + str(timestamp)
            tmpsource = self.pathParser(self.config['destination'] + lastdir)
            bckindex = self.loadIndexFile(tmpsource + "index.gz")
            destbase = self.pathParser(pathdest)
            for item in bckindex:
                try:
                    if item['path'] != "":  # Comprobamos que no es ori-path
                        sourcepath = self.pathParser(item['path'].replace(path,
                                                                          tmpsource + "files/"), endp=False)
                        sourcepath = sourcepath.replace("//", "/")
                        sourcepath = sourcepath.replace("\\\\", "\\")
                        letravol = ":\\"
                        if item['path'][1:3] == ":\\":
                            letravol = item['path'][0:3]
                        destpath = destbase + item['path'].replace(letravol,"\\")
                        destpath = destpath.replace("//", "/")
                        destpath = destpath.replace("\\\\", "\\")
                        destpath = self.pathParser(destpath, endp=False)
                        # Si es Directorio lo crea en destino
                        if item['attr']['type'] == 'd':
                            try:
                                os.makedirs(destpath)
                                os.chmod(destpath, item['attr']['mode'])
                                try:
                                    os.chown(destpath,
                                             item['attr']['uid'],
                                             item['attr']['gid'])
                                except:
                                    pass
                            except OSError:
                                pass
                            except Exception as e:
                                self.writeLine("\t[!] {0}".format(str(e)),
                                               logtype="error")
                        else:
                            # Si es fichero copia el fichero con gzip:
                            try:
                                self.restoreFileGzip(sourcepath, destpath)
                                os.chmod(destpath, item['attr']['mode'])
                                try:
                                    os.chown(destpath,
                                             item['attr']['uid'],
                                             item['attr']['gid'])
                                except:
                                    pass
                            except Exception as e:
                                self.writeLine("\t[!] {0}".format(str(e)),
                                               logtype="error")
                except KeyError:
                    pass
            if dbres:
                self.writeLine("[-] Full backup '{0}' Restored".format(path))
            else:
                self.writeLine("[-] Full backup '{0}' restore Failed".format(path))
                continue
            # TODO ajustar errores de tipo de fichero y revisar el exception del copyfiles

    def restoreIncremental(self, backupid, pathdest, pathsource="/"):
        backupdata = self.getBackupIncremental(backupid[0])
        destbase = self.pathParser(pathdest)
        indexesfilesarr = []
        fusionedindex = []
        if len(backupdata) > 0:
            lastindex = backupdata[0]
            backupdata.remove(lastindex)
            lastbckindexfile = self.getIndexFilePath(lastindex)
            path = lastindex[3]
            self.writeLine("[-] Incremental backup '{0}' restoring on {1} started".format(path, pathdest))
            for data in backupdata:
                indexesfilesarr.append(self.getIndexFilePath(data))
            fusionedindex = self.compareLastIndexRestore(indexesfilesarr, lastbckindexfile)
            ####
            for item in fusionedindex:
                try:
                    if not "status" in item.keys() and item['path'] != "":  # Comprobamos que no es ori-path
                        tmpsource = item['from']
                        sourcepath = item['path'].replace(path, tmpsource)
                        sourcepath = sourcepath.replace("//", "/")
                        sourcepath = sourcepath.replace("\\\\", "\\")
                        letravol = ":\\"
                        if item['path'][1:3] == ":\\":
                            letravol = item['path'][0:3]
                        destpath = destbase + item['path'].replace(letravol, "\\")
                        destpath = destpath.replace("//", "/")
                        destpath = destpath.replace("\\\\", "\\")
                        # print destpath
                        # Si es Directorio lo crea en destino
                        if item['attr']['type'] == 'd':
                            try:
                                os.makedirs(destpath)
                                os.chmod(destpath, item['attr']['mode'])
                                os.chown(destpath,
                                         item['attr']['uid'],
                                         item['attr']['gid'])
                            except OSError:
                                pass
                            except AttributeError:
                                pass
                        else:
                            # Si es fichero copia el fichero con gzip:
                            try:
                                self.restoreFileGzip(sourcepath, destpath)
                                os.chmod(destpath, item['attr']['mode'])
                                os.chown(destpath,
                                         item['attr']['uid'],
                                         item['attr']['gid'])
                            except AttributeError:
                                pass
                            except Exception as e:
                                self.writeLine("\t[!] " + str(e), logtype="error")
                except KeyError:
                    pass
            self.writeLine("[-] Incremental backup '{0}' Restored".format(path))
        else:
            self.writeLine("[!] Restore failed", logtype="error")
            exit()
        # 1- consultar en db el id del backup incremental -> getBackupIncremental(self,path,bckincrementalid)
        # 2- Consultar en db los datos del backup full anterior -> getBackupIncremental
        # 3- Comparar los index (hay que crear un metodo de 
        # comparacion de indices para restores evitando que se tome 
        # como eliminados los ficheros que no aparezcan en el segundo indice, 
        # y tomando como eliminados los status:del) -> compareLastIndexRestore
        # 4- Restaurar la version mas actual de los ficheros evitando 
        # restaurar eliminados en incremental
        pass

    # TODO restorefile
    def restoreOnceFileOfBackup(self, backupid, filepath, pathdest):
        query = "SELECT * FROM backups WHERE id={0}".format(backupid)
        dbres = self.getDataFromDB(self.config['localdb'], query)
        timestamp = dbres[0][1]
        path = dbres[0][3]
        if dbres != []:
            self.writeLine("[-] Full backup '{0}' restoring on {1} started\n".format(path, pathdest))
        else:
            self.writeLine("[-] Full backup restore '{0}' Failed\n".format(path))
        if path == "/" or path == "c:\\":
            lastdir = self.getLastDir("/_ROOT_DIR_") + "/full_" + str(timestamp)
        else:
            lastdir = self.getLastDir(path) + "/full_" + str(timestamp)
        tmpsource = self.pathParser(self.config['destination'] + lastdir)
        sourcepath = self.pathParser(filepath.replace(path,
                                                      tmpsource + "files/"), endp=False)
        destbase = self.pathParser(pathdest)
        destpath = destbase + filepath
        destpath = destpath.replace("//", "/")
        destpath = destpath.replace("\\\\", "\\")
        destpath = self.pathParser(destpath, endp=False)
        self.restoreFileGzip(sourcepath, pathdest)

    def getIndexFilePath(self, data):  # data es la fila de db backup
        path = data[3]
        if path == "/" or path == "c:\\":
            root = self.getLastDir("/_ROOT_DIR_")
            lastdir = "{0}/{1}_{2}".format(root, data[2], data[1])
        else:
            pathparsed = self.getLastDir(path)
            lastdir = "{0}/{1}_{2}".format(pathparsed, data[2], data[1])
        tmpsource = self.pathParser(self.config['destination'] + lastdir) + "index.gz"
        return tmpsource

    def setDataToDB(self, filename, query):
        try:
            con = sqlite3.connect(filename)
            cursor = con.cursor()
            cursor.execute(query)
            con.commit()
            con.close()
            return True
        except Exception:
            return False

    def getDataFromDB(self, filename, query):
        con = sqlite3.connect(filename)
        cursor = con.cursor()
        cursor.execute(query)
        res = cursor.fetchall()
        return res

    def getBackups(self, path, bcktype='full'):
        if bcktype == "all":
            bcktype = "%"
        query = "SELECT * FROM backups WHERE path='" + path + "' AND type like '" + \
                bcktype + "' ORDER BY id"
        bcklist = self.getDataFromDB(self.config['localdb'], query)
        return bcklist

    def getBackupIncremental(self, bckincrementalid, path=""):
        if path != "":
            query = "SELECT * FROM backups WHERE path='{0}' AND type='full'" + \
                    " AND id<{1} ORDER BY id DESC LIMIT 1"
            query = query.format(path, bckincrementalid)
        else:
            query = "SELECT * FROM backups WHERE type='full' AND id<{0} ORDER BY id DESC LIMIT 1"
            query = query.format(bckincrementalid)
        bckres = []
        bcklist = self.getDataFromDB(self.config['localdb'], query)
        if len(bcklist) > 0:
            query = "SELECT * FROM backups WHERE path='{0}' AND type='incremental'" + \
                    " AND id<={1} AND id>={2} ORDER BY id DESC LIMIT 1"
            query = query.format(bcklist[0][3], bckincrementalid, bcklist[0][0])
            bcklisttmp = self.getDataFromDB(self.config['localdb'], query)
            for incremental in bcklisttmp:
                bckres.append(incremental)
            bckres.append(bcklist[0])
        return bckres

    def getPaths(self):
        return self.paths

    def runBackups(self):
        self.writeLine("[-] Checking if is the time to do full backups")
        for full in self.config['full']:
            datetmp = full.split(" ")
            weekday = datetime.datetime.now().strftime("%a").lower()
            monday = datetime.datetime.now().strftime("%d").lower()
            time = datetime.datetime.now().strftime("%H:%M").lower()
            if (datetmp[0] == weekday or datetmp[0] == monday) and datetmp[1] == time:
                t1 = threading.Thread(target=self.doFullBackup(), args=(None,))
                t1.start()
        self.writeLine("[-] Checking if is the time to do incremental backups\n")
        for incr in self.config['incremental']:
            datetmp = incr.split(" ")
            weekday = datetime.datetime.now().strftime("%a").lower()
            monday = datetime.datetime.now().strftime("%d").lower()
            time = datetime.datetime.now().strftime("%H:%M").lower()
            if (datetmp[0] == weekday or datetmp[0] == monday) and datetmp[1] == time:
                t1 = threading.Thread(target=self.doIncrementalBackup(), args=(None,))
                t1.start()
        # >>> print "Or like this: " ,datetime.datetime.now().strftime("%a %y-%m-%d-%H-%M")
        # Or like this:  Wed 17-11-08-02-44

    def launchDaemon(self):
        timetowait = 50
        while True:
            self.runBackups()
            self.writeLine("[-] Waiting {0} seconds to recheck".format(timetowait))
            time.sleep(timetowait)


def main():
    bsc = BackSecClient()
    try:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(help='commands')
        # modo demonio
        dparser = subparsers.add_parser('daemon', help='Activate daemon mode')
        dparser.add_argument("daemon", action='store_true',
                             default=True, help="Activate daemon mode")
        # Run policy once
        rpparser = subparsers.add_parser('runpolicy', help='Run backup policy one time')
        rpparser.add_argument('runpolicy', action='store_true', default=True,
                              help='Run backup policy one time')
        rpparser.add_argument('--btype', '-BT', action='store', default='full',
                              choices=('incremental', 'full'),
                              help='Backup type (full or incremental)')
        # listar directorios gestionados
        ldparser = subparsers.add_parser('listdirs', help='List backup directories')
        ldparser.add_argument('listdirs', action='store_true', default=True,
                              help='List backup directories')
        # List backups
        lbparser = subparsers.add_parser('listbackups', help='List backups')
        lbparser.add_argument('listbackups', action='store_true', default=True,
                              help='List backups')
        lbparser.add_argument('directory', action='store', help='Backup source directory')
        lbparser.add_argument('--btype', '-BT', default='all', action='store', dest='btype',
                              choices=('all', 'incremental', 'full'),
                              help='Select backupt to find (full,incremental or all)')
        # restore backups
        # TODO hacer que se seleccione el tipo de backup en base a la bbdd sin necesidad de indicerlo
        rbparser = subparsers.add_parser('restore', help='Restore backups')
        rbparser.add_argument('restore', action='store_true', default=True,
                              help='Restore backups')
        rbparser.add_argument('backupid', action='store', help='Backup id')
        rbparser.add_argument('destination', action='store', help='Restore destination directory')
        rbparser.add_argument('--btype', '-BT', default='all', action='store', dest='btype',
                              choices=('incremental', 'full'),
                              help='Select backupt to find (full,incremental)')
        # TODO restorefile
        # restore once file
        # TODO hacer que se seleccione el tipo de backup en base a la bbdd sin necesidad de indicerlo
        rbparser = subparsers.add_parser('restorefile', help='Restore once file')
        rbparser.add_argument('restorefile', action='store_true', default=True,
                              help='Restore once file')
        rbparser.add_argument('backupid', action='store', help='Backup id')
        rbparser.add_argument('filepath', action='store', help='File path on the system')
        rbparser.add_argument('destination', action='store', help='Restore destination directory')
        rbparser.add_argument('--btype', '-BT', default='all', action='store', dest='btype',
                              choices=('incremental', 'full'),
                              help='Select backupt to find (full,incremental)')
        args = parser.parse_args()
        if 'daemon' in args and args.daemon:
            bsc.launchDaemon()
        elif 'listdirs' in args and args.listdirs:
            bsc.writeLine("[-] List the directories saved:\n")
            for direc in bsc.getPaths():
                bsc.writeLine("\t{0}\n".format(direc))
        elif 'listbackups' in args and args.listbackups:
            bsc.writeLine("[-] List the backups saved:\n")
            counter = 0
            for direc in bsc.getBackups(args.directory, bcktype=args.btype):
                counter += 1
                datet = datetime.datetime.fromtimestamp(int(direc[1])).strftime('%Y-%m-%d %H:%M:%S')
                bsc.writeLine("\t-{0}. {1} {2} {3} {4} (id: {5})\n".format(counter,
                                                                           direc[3], direc[2], datet, direc[4],
                                                                           direc[0]))
        elif 'runpolicy' in args and args.runpolicy:
            bsc.writeLine("[-] Running policy {0} one time:\n".format(args.btype))
            if args.btype == "full":
                bsc.doFullBackup()
            elif args.btype == "incremental":
                bsc.doIncrementalBackup()
        elif 'restore' in args and args.restore:
            bsc.writeLine("[-] Running restore {0} one time:\n".format(args.btype))
            if args.btype == "full":
                bsc.restoreFull([args.backupid], args.destination)
            elif args.btype == "incremental":
                bsc.restoreIncremental([args.backupid], args.destination)
        # TODO restorefile
        elif 'restorefile' in args and args.restorefile:
            bsc.writeLine("[-] Running restore {0} one time:\n".format(args.btype))
            bsc.restoreOnceFileOfBackup(args.backupid, args.filepath, args.destination)
    except Exception as e:
        bsc.writeLine("[!] An error ocurred {0}".format(e), logtype="error")
    except KeyboardInterrupt:
        bsc.writeLine("[-] You have chosen exit\n")
    #


if __name__ == "__main__":
    main()

# TODO Hacer que el restore se haga full o incremental dependiendo del backup y no del usuario     
# TODO Sustituir write's por self.writeLine
# TODO hacer que se pueda restaurar un fichero

