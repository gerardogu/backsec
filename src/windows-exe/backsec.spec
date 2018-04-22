# -*- mode: python -*-

block_cipher = None


a = Analysis(['..\\backsec.py'],
             pathex=['C:\\Users\\admin\\Desktop\\ggusoft-backsec\\windows-exe'],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='backsec',
          debug=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=True )
