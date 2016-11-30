#include "Logging.h"
#include "Conv.h"
#include <errno.h>

#define	SIZE	4096

using namespace Plan9;
using namespace Plan9::Common;
using namespace Plan9::Conversion;

int
Logging::print(const char *fmt, ...)
{
	char buf[SIZE], *out;
	va_list arg, temp;
	int n;

	va_start(arg, fmt);
	va_copy(temp, arg);
	out = doprint(buf, buf+SIZE, fmt, &temp);
	va_end(temp);
	va_end(arg);
	n = write(1, buf, (long)(out-buf));
	return n;
}

int
Logging::fprint(int f, const char *fmt, ...)
{
	char buf[SIZE], *out;
	va_list arg, temp;
	int n;

	va_start(arg, fmt);
	va_copy(temp, arg);
	out = doprint(buf, buf+SIZE, fmt, &temp);
	va_end(temp);
	va_end(arg);
	n = write(f, buf, (long)(out-buf));
	return n;
}

int
Logging::sprint(char *buf, const char *fmt, ...)
{
	char *out;
	va_list arg, temp;
	int scol;

	scol = printcol;
	va_start(arg, fmt);
	va_copy(temp, arg);
	out = doprint(buf, buf+SIZE, fmt, &temp);
	va_end(temp);
	va_end(arg);
	printcol = scol;
	return out-buf;
}

int
Logging::snprint(char *buf, int len, const char *fmt, ...)
{
	char *out;
	va_list arg, temp;
	int scol;

	scol = printcol;
	va_start(arg, fmt);
	va_copy(temp, arg);
	out = doprint(buf, buf+len, fmt, &temp);
	va_end(temp);
	va_end(arg);
	printcol = scol;
	return out-buf;
}

char*
Logging::seprint(char *buf, char *e, const char *fmt, ...)
{
	char *out;
	va_list arg, temp;
	int scol;

	scol = printcol;
	va_start(arg, fmt);
	va_copy(temp, arg);
	out = doprint(buf, e, fmt, &temp);
	va_end(temp);
	va_end(arg);
	printcol = scol;
	return out;
}

char*
Logging::smprint(const char *fmt, ...)
{
	char buf[SIZE];
	va_list arg, temp;
	int scol;

	scol = printcol;
	va_start(arg, fmt);
	va_copy(temp, arg);
	doprint(buf, buf+sizeof(buf), fmt, &temp);
	va_end(temp);
	va_end(arg);
	printcol = scol;
	return strdup(buf);
}

void
Logging::sysfatal(const char *fmt, ...)
{
        char buf[1024];
        va_list va, temp;

fprint(2, "sysfatal entry\n");
        va_start(va, fmt);
        va_copy(temp, va);
        doprint(buf, buf+sizeof buf, fmt, &temp);
        va_end(temp);
        va_end(va);
        fprint(2, "u9fs: %s\n", buf);
        fprint(2, "last unix error: %s\n", strerror(errno));
        exit(1);
}

char*
Logging::strecpy(char *to, char *e, char *from)
{
        if(to >= e)
                return to;
        to = reinterpret_cast<char *>(memccpy(to, from, '\0', e - to));
        if(to == NULL){
                to = e - 1;
                *to = '\0';
        }
        return to;
}

int
Logging::getfields(char *str, char **args, int max, int mflag, const char *set)
{
	Rune r;
	int nr, intok, narg;

	if(max <= 0)
		return 0;

	narg = 0;
	args[narg] = str;
	if(!mflag)
		narg++;
	intok = 0;
	for(;; str += nr) {
		nr = Plan9::Conversion::chartorune(&r, str);
		if(r == 0)
			break;
		if(utfrune(set, r)) {
			if(narg >= max)
				break;
			*str = 0;
			intok = 0;
			args[narg] = str + nr;
			if(!mflag)
				narg++;
		} else {
			if(!intok && mflag)
				narg++;
			intok = 1;
		}
	}
	return narg;
}

int
Logging::tokenize(char *str, char **args, int max)
{
	return getfields(str, args, max, 1, " \t\n\r");
}

const char*
Logging::utfrune(const char *s, long c)
{
	long c1;
	Rune r;
	int n;

	if(c < Runesync)		/* not part of utf sequence */
		return strchr(s, c);

	for(;;) {
		c1 = *(uchar*)s;
		if(c1 < Runeself) {	/* one byte rune */
			if(c1 == 0)
				return 0;
			if(c1 == c)
				return s;
			s++;
			continue;
		}
		n = Conversion::chartorune(&r, s);
		if(r == c)
			return s;
		s += n;
	}
	return 0;
}

