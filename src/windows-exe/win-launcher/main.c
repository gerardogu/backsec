#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

int Run( char * Command );
char *replacestr(char *string, char *sub, char *replace);

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
    char * pathtmp = GetCommandLine();
    char * pathtmp2 = replacestr(pathtmp,"launcher.exe\"" , "backsec.exe\" daemon" );
    pathtmp2[0] = '"';
    int i = 0;
    char * path = malloc(strlen(pathtmp2)*sizeof(char));
    for (i = 1;i<strlen(pathtmp2);i++){
        path[i-1]=pathtmp2[i];
    }
    /*DEBUG*/
    /*
    FILE * fp = fopen("c:\\testlauncher-c.txt","w");
    fprintf(fp,"Linea: %s\n",GetCommandLine());
    fprintf(fp,"Linea: %s\n",path);
    fclose(fp);
    */
    /*FIN DEBUG*/
    Run(path);
    return 0;
}

int Run( char * Command ) {
  STARTUPINFO si;
  PROCESS_INFORMATION pi;

  si.cb = sizeof(STARTUPINFO);
  si.lpReserved = NULL;
  si.lpDesktop = NULL;
  si.lpTitle = 0;
  si.dwX = si.dwY = si.dwXSize = si.dwYSize =
  si.dwXCountChars = si.dwYCountChars = si.dwFlags = 0;
  //si.wShowWindow = SW_NORMAL;
  //added by ger
  si.wShowWindow = SW_HIDE;
  //si.dwCreationFlags = CREATE_NO_WINDOW;
  //
  si.lpReserved2 = NULL;
  si.cbReserved2 = 0;
  si.hStdInput = si.hStdOutput = si.hStdError = 0;
  return CreateProcess(0, Command, 0, 0, 1,CREATE_NO_WINDOW, 0, 0, &si, & pi);
  //return CreateProcess(0, Command, 0, 0, 1, 0, 0, 0, &si, & pi);
}

char *replacestr(char *string, char *sub, char *replace)
{
    if(!string || !sub || !replace) return NULL;
    char *pos = string; int found = 0;
    while((pos = strstr(pos, sub))){
        pos += strlen(sub);
        found++;
    }
    if(found == 0) return NULL;
    int size = ((strlen(string) - (strlen(sub) * found)) + (strlen(replace) * found)) + 1;
    char *result = (char*)malloc(size);
    pos = string; 
    char *pos1;
    while((pos1 = strstr(pos, sub))){
        int len = (pos1 - pos);
        strncat(result, pos, len);
        strncat(result, replace, strlen(replace));
        pos = (pos1 + strlen(sub));
    }
    if(pos != (string + strlen(string)))
        strncat(result, pos, (string - pos));
    return result;
}

