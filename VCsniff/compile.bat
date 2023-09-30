@ECHO OFF

cl.exe /nologo /W0 vcsniff-iat.cpp /MT /link /DLL /OUT:vcsniff-iat.dll

del *.obj *.lib *.exp