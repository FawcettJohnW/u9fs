#include "P9Common.h"
#include "Logging.h"
#include <sys/time.h>

using namespace Plan9;
using namespace Plan9::Common;

int Plan9::Common::seeded=1;
char* argv0;
char* root = NULL;

// Support routines
long Plan9::Common::getseed(void)
{
	struct timeval tv;
	long seed;
	int fd, len;

	len = 0;
	fd = open("/dev/urandom", O_RDONLY);
	if(fd > 0){
		len = read(fd, &seed, sizeof(seed));
		close(fd);
	}
	if(len != sizeof(seed)){
		gettimeofday(&tv, NULL);
		seed = tv.tv_sec ^ tv.tv_usec ^ (getpid()<<8);
	}
	return seed;
}

void Plan9::Common::randombytes(uchar *r, uint nr)
{
	int i;
	ulong l;

	if(!Plan9::Common::seeded){
		Plan9::Common::seeded=1;
		srand48(getseed());
	}
	for(i=0; i+4<=nr; i+=4,r+=4){
		l = (ulong)mrand48();
		r[0] = l;
		r[1] = l>>8;
		r[2] = l>>16;
		r[3] = l>>24;
	}
	if(i<nr){
		l = (ulong)mrand48();
		switch(nr-i){
		case 3:
			r[2] = l>>16;
		case 2:
			r[1] = l>>8;
		case 1:
			r[0] = l;
		}
	}
}

void*
Plan9::Common::emalloc(size_t n)
{
	void *p;
Logging::fprint(2, "emalloc entry\n");

	if(n == 0)
		n = 1;
	p = malloc(n);
	if(p == 0)
		Logging::sysfatal("malloc(%ld) fails", (long)n);
	memset(p, 0, n);
	return p;
}

void*
Plan9::Common::erealloc(void *p, size_t n)
{
Logging::fprint(2, "erealloc entry\n");
	if(p == 0)
		p = malloc(n);
	else
		p = realloc(p, n);
	if(p == 0)
		Logging::sysfatal("realloc(..., %ld) fails", (long)n);
	return p;
}

char*
Plan9::Common::estrdup(char *p)
{
Logging::fprint(2, "strdup entry\n");
	p = strdup(p);
	if(p == 0)
		Logging::sysfatal("strdup(%.20s) fails", p);
	return p;
}

char *
Plan9::Common::common_defrog(char *s)
{
        char *d, *dst, buf[3];
Logging::fprint(2, "common_defrog entry\n");

        d = dst = reinterpret_cast<char *>(emalloc(strlen(s) + 1));
        for(; *s; s++)
                if(*s == '\\' && strlen(s) >= 3){
                        buf[0] = *++s;                  /* skip \ */
                        buf[1] = *++s;
                        buf[2] = 0;
                        *d++ = strtoul(buf, NULL, 16);
                } else
                        *d++ = *s;
        *d = 0;
        return dst;
}

char*
Plan9::Common::estrpath(char *p, char *q, int frog)
{
	char *r, *s;
Logging::fprint(2, "estrpath entry\n");

	if(strcmp(q, "..") == 0){
		r = estrdup(p);
		if((s = strrchr(r, '/')) && s > r)
			*s = '\0';
		else if(s == r)
			s[1] = '\0';
		return r;
	}

	if(frog)
		q = common_defrog(q);
	else
		q = strdup(q);
	r = reinterpret_cast<char *>(emalloc(strlen(p)+1+strlen(q)+1));
	strcpy(r, p);
	if(r[0]=='\0' || r[strlen(r)-1] != '/')
		strcat(r, "/");
	strcat(r, q);
	free(q);
	return r;
}

