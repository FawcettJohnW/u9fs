#ifndef __P9COMMON_H_
#define __P9COMMON_H_

#include <string>
#include <iostream>
#include <ostream>

/*--------------------------------------------------------------------------------*/
/**
    \file        plan9common.h

    \brief       Common declarations, structs, and other data for u9fs-d
    
    \date        11-17-16 
    
*/
/*----------------------------------------------------------------------------*/
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
/* magic to get SUSV2 standard, including pread, pwrite*/
// #define _XOPEN_SOURCE 500
#endif
/* magic to get 64-bit pread/pwrite */
// #define _LARGEFILE64_SOURCE
/* magic to get 64-bit stat on Linux, maybe others */
#define _FILE_OFFSET_BITS 64

#ifdef sgi
#define _BSD_TYPES      1       /* for struct timeval */
#include <sys/select.h>
#define _BSD_SOURCE     1       /* for ruserok */
/*
 * SGI IRIX 5.x doesn't allow inclusion of both inttypes.h and
 * sys/types.h.  These definitions are the ones we need from
 * inttypes.h that aren't in sys/types.h.
 *
 * Unlike most of our #ifdef's, IRIX5X must be set in the makefile.
 */
#ifdef IRIX5X
#define __inttypes_INCLUDED
typedef unsigned int            uint32_t;
typedef signed long long int    int64_t;
typedef unsigned long long int  uint64_t;
#endif /* IRIX5X */
#endif /* sgi */


#ifdef sun      /* sparc and __svr4__ are also defined on the offending machine */
#define __EXTENSIONS__  1       /* for struct timeval */
#endif

#include <inttypes.h>           /* for int64_t et al. */
#include <stdlib.h>
#include <stdarg.h>             /* for va_list, vararg macros */
#ifndef va_copy
#ifdef __va_copy
#define va_copy __va_copy
#else
#define va_copy(d, s)   memmove(&(d), &(s), sizeof(va_list))
#endif /* __va_copy */
#endif /* va_copy */
#include <sys/types.h>
#include <string.h>             /* for memmove */
#include <fcntl.h>      /* for O_RDONLY, etc. */
#include <unistd.h>             /* for write */

#define ulong p9ulong           /* because sys/types.h has some of these sometimes */
#define ushort p9ushort
#define uchar p9uchar
#define uint p9uint
#define vlong p9vlong
#define uvlong p9uvlong
#define u32int p9u32int

typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned long ulong;
typedef unsigned int uint;
typedef int64_t vlong;
typedef uint64_t uvlong;
typedef uint32_t u32int;
typedef uint64_t u64int;
typedef ushort Rune;

#define nelem(x)        (sizeof(x)/sizeof((x)[0]))
#ifndef offsetof
#define offsetof(s, m)  (ulong)(&(((s*)0)->m))
#endif
#define assert(x)       if(x);else _assert("x")

static char p9_es[]="";

extern char *argv0;

#define ARGBEGIN        for((void)(argv0||(argv0=*argv)),argv++,argc--;\
                            argv[0] && argv[0][0]=='-' && argv[0][1];\
                            argc--, argv++) {\
                                char *_args, *_argt;\
                                Rune _argc;\
                                _args = &argv[0][1];\
                                if(_args[0]=='-' && _args[1]==0){\
                                        argc--; argv++; break;\
                                }\
                                _argc = 0;\
                                while(*_args && (_args += Plan9::Conversion::chartorune(&_argc, _args)))\
                                switch(_argc)
#define ARGEND          SET(_argt);USED(_argt);USED(_argc);USED(_args);}\
                                        USED(argv);USED(argc);
#define ARGF()          (_argt=_args, _args=p9_es,\
                                (*_argt? _argt: argv[1]? (argc--, *++argv): 0))
#define EARGF(x)                (_argt=_args, _args=p9_es,\
                                (*_argt? _argt: argv[1]? (argc--, *++argv): ((x), abort(), (char*)0)))

#define ARGC()          _argc

#define SET(x)  (x) = 0
#define USED(x) (void)(x)

#define S_ISSPECIAL(m) (S_ISCHR(m) || S_ISBLK(m) || S_ISFIFO(m))

#define DESKEYLEN 7
#define IOHDRSZ         24      /* ample room for Twrite/Rread header (iounit) */

#define OREAD   0       /* open for read */
#define OWRITE  1       /* write */
#define ORDWR   2       /* read and write */
#define OEXEC   3       /* execute, == read but check execute permission */
#define OTRUNC  16      /* or'ed in (except for exec), truncate file first */
#define OCEXEC  32      /* or'ed in, close on exec */
#define ORCLOSE 64      /* or'ed in, remove on close */
#define OEXCL   0x1000  /* or'ed in, exclusive use */

/* bits in Qid.type */
#define QTDIR           0x80            /* type bit for directories */
#define QTAPPEND        0x40            /* type bit for append only files */
#define QTEXCL          0x20            /* type bit for exclusive use files */
#define QTMOUNT         0x10            /* type bit for mounted channel */
#define QTAUTH          0x08            /* type bit for authentication files */
#define QTTMP           0x04            /* type bit for non backed-up files */
#define QTSYMLINK       0x02            /* type bit for symbolic link */
#define QTLINK          0x01            /* type bit for hard link */
#define QTFILE          0x00            /* plain file */

/* bits in Dir.mode */
#define DMDIR           0x80000000      /* mode bit for directories */
#define DMAPPEND        0x40000000      /* mode bit for append only files */
#define DMEXCL          0x20000000      /* mode bit for exclusive use files */
#define DMMOUNT         0x10000000      /* mode bit for mounted channel */
#define DMREAD          0x4             /* mode bit for read permission */
/* 9P2000.u extensions */
#define P9_DMSYMLINK    0x02000000      /* mode bit for symbolic links */
#define P9_DMLINK       0x01000000      /* mode bit for hard links */
#define P9_DMDEVICE     0x00800000      /* mode bit for device special files */
#define P9_DMNAMEDPIPE  0x00200000      /* mode bit for named pipes */
#define P9_DMSOCKET     0x00100000      /* mode bit for domain sockets */
#define P9_DMSETUID     0x00080000      /* mode bit for set UID */
#define P9_DMSETGID     0x00040000      /* mode bit for set GID */
#define P9_DMSETVTX     0x00010000      /* mode bit for sticky bit */
namespace Plan9
{
    namespace Common
    {
        extern char *logfile;

        enum {
                Tdot = 1,
                Tdotdot
        };
        
        enum {
                P9P1,
                P9P2000
        };

        /**
         * struct p9_str - length prefixed string type
         * @len: length of the string
         * @str: the string
         *
         * The protocol uses length prefixed strings for all
         * string data, so we replicate that for our internal
         * string members.
         */
        
        struct p9_str {
                ushort len;
                char *str;
        };
        
        typedef
        struct Qid
        {
                vlong   path;
                ulong   vers;
                uchar   type;

                Qid( void )
                : path(NULL), vers(0), type(0)
                {}
        } Qid;

        typedef
        struct Dir {
                /* system-modified data */
                ushort  type;   /* server type */
                uint    dev;    /* server subtype */
                /* file data */
                Qid     qid;    /* unique id from server */
                ulong   mode;   /* permissions */
                ulong   atime;  /* last read time */
                ulong   mtime;  /* last write time */
                vlong   length; /* file length: see <u.h> */
                char    *name;  /* last element of path */
                char    *uid;   /* owner name */
                char    *gid;   /* group name */
                char    *muid;  /* last modifier name */
                char    *extension;        /* 9p2000.u extensions */
                ulong   n_uid;             /* 9p2000.u extensions */
                ulong   n_gid;             /* 9p2000.u extensions */
                ulong   n_muid;            /* 9p2000.u extensions */

                Dir( void )
                : type(0), dev(0), mode(0), atime(0), mtime(0), length(0), name(NULL),
                  uid(NULL), gid(NULL), muid(NULL), extension(NULL), n_uid(0), n_gid(0),
                  n_muid(0)
                {}
        } Dir;

        extern int     chatty9p;
        extern char   *autharg;
        extern ulong   msize;
        extern int     network;
        extern char   *defaultuser;
        extern char    hostname[256];
        extern char    remotehostname[256];
        extern char   *root;
        extern int     old9p;

        void*   emalloc(size_t);
        void*   erealloc(void*, size_t);
        char*   estrdup(char*);
        char*   estrpath(char*, char*, int);
        int     okuser(char*);

        // defrog outside the transport object
        char*   common_defrog(char *s);

        // Randomness stuff
        long getseed( void );
        extern int seeded;
        void randombytes(uchar *r, uint nr);

    } // Namespace common
} // Namespace Plan9
    
#endif // __P9COMMON_H_
