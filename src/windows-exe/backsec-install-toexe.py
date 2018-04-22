from distutils.core import setup
import py2exe, sys, os

sys.argv.append('py2exe')


setup( 
  options = {         
    'py2exe' : {
        'compressed': 1, 
        'optimize': 2,
        'bundle_files': 1, #Options 1 & 2 do not work on a 64bit system
        'dist_dir': 'Backsec-EXE',  # Put .exe in dist/
        'xref': False,
        'skip_archive': False,
        'ascii': False,
        }
        },                   
  zipfile=None, 
  #windows = ['../backsec.py'],
  windows =[{
    "script": './backsec-install.py',      
    #"icon_resources": [(0, "favicon.ico")], ### Icon to embed into the PE file.
    "dest_base" : "backsec-install",}]
  
)

#windows puede cambiarse por console