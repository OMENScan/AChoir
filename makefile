# AChoir MakeFile
# Added -lmpr for WNet Library (WNetUseConnection) 08/22/15

SRC = AChoir.c
CFLAGS = -DCURL_STATICLIB
INCLUDES = -I..\LIBCURL_HOME\include -I../include
LIBS = -lws2_32 -lmpr
LIBX = ..\LIBCURL_HOME\lib\libcurl.a

All : AChoir.exe

AChoir.exe : AChoir.o
	gcc -o AChoir.exe AChoir.o $(LIBX) $(LIBS)

AChoir.o : AChoir.c
	gcc -c $(CFLAGS) $(INCLUDES) $(SRC)
