AC_INIT([Netstat-EMB], [0.1.2])

AC_PROG_CC
AC_LANG(C)

AC_DEFINE([LITTLE], [0])
AC_DEFINE([BIG], [1])

if test "$ENDIANESS" == ""
then
	if [ basename $CC | grep -e armeb -e mipseb ]
	then
		echo "auto detected big endian target architecture"
		ENDIANESS=be
	else
		echo "auto detected little endian architecture"
		ENDIANESS=le
	fi
fi

if test "$ENDIANESS" == "be"
then
	AC_DEFINE([ENDIANESS], [BIG])
else
	AC_DEFINE([ENDIANESS], [LITTLE])
fi

cp confdefs.h config.h

AC_OUTPUT(Makefile)
