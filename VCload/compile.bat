@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp *.cpp /link /OUT:vcload.exe /SUBSYSTEM:WINDOWS /MACHINE:x64
del *.obj