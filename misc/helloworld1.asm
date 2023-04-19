.386
.model flat, stdcall
option casemap :none

include windows.inc
include kernel32.inc
include user32.inc

includelib kernel32.lib
includelib user32.lib

.data
szCaption db 'MessageBox', 0
szText db 'Hello World 1!', 0

.code
start:
    invoke MessageBox, NULL, offset szText, offset szCaption, MB_OK
    invoke ExitProcess, 0
end start