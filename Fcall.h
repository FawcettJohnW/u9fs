#ifndef __P9FCALL_H_
#define __P9FCALL_H_
#include "P9Common.h"
#include "Conv.h"

// #define	VERSION9P	"9P2000"
#define	VERSION9P	"9P2000.u"
#define	MAXWELEM	16

#define	GBIT8(p)	((p)[0])
#define	GBIT16(p)	((p)[0]|((p)[1]<<8))
#define	GBIT32(p)	((p)[0]|((p)[1]<<8)|((p)[2]<<16)|((p)[3]<<24))
#define	GBIT64(p)	((ulong)((p)[0]|((p)[1]<<8)|((p)[2]<<16)|((p)[3]<<24)) |\
				((vlong)((p)[4]|((p)[5]<<8)|((p)[6]<<16)|((p)[7]<<24)) << 32))

#define	PBIT8(p,v)	(p)[0]=(v)
#define	PBIT16(p,v)	(p)[0]=(v);(p)[1]=(v)>>8
#define	PBIT32(p,v)	(p)[0]=(v);(p)[1]=(v)>>8;(p)[2]=(v)>>16;(p)[3]=(v)>>24
#define	PBIT64(p,v)	(p)[0]=(v);(p)[1]=(v)>>8;(p)[2]=(v)>>16;(p)[3]=(v)>>24;\
			(p)[4]=(v)>>32;(p)[5]=(v)>>40;(p)[6]=(v)>>48;(p)[7]=(v)>>56

#define	BIT8SZ		1
#define	BIT16SZ		2
#define	BIT32SZ		4
#define	BIT64SZ		8
#define	QIDSZ	(BIT8SZ+BIT32SZ+BIT64SZ)

/* STATFIXLEN includes leading 16-bit count */
/* The count, however, excludes itself; total size is BIT16SZ+count */
// #define STATFIXLEN	(BIT16SZ+QIDSZ+5*BIT16SZ+4*BIT32SZ+1*BIT64SZ)	/* amount of fixed length data in a stat buffer */

// u16:  size, type
// u32:  dev, mode, atime, mtime, n_uid, n_gid, n_muid
// u64:  length
// Qid:  Qid
// str:  name, uid, gid, muid, extension (each str takes 1 16-bit number for size)
#define STATFIXLEN	(BIT16SZ+QIDSZ+6*BIT16SZ+7*BIT32SZ+1*BIT64SZ)	/* amount of fixed length data in a stat buffer */

#define	MAXMSG		10000	/* max header sans data */
#define	NOTAG		~0U	/* Dummy tag */
#define	IOHDRSZ		24	/* ample room for Twrite/Rread header (iounit) */

#define MAXWELEM        16

using namespace Plan9;
using namespace Plan9::Common;

namespace Plan9
{
    namespace Fcalls
    {
        typedef
        struct	Fcall
        {
	        uchar	type;
	        u32int	fid;
	        ushort	tag;
        
	        u32int	msize;		/* Tversion, Rversion */
	        char	*version;	/* Tversion, Rversion */
        
	        u32int	oldtag;		/* Tflush */
        
	        char	*ename;		/* Rerror */
        
	        Qid	qid;		/* Rattach, Ropen, Rcreate */
	        u32int	iounit;		/* Ropen, Rcreate */
        
	        char	*uname;		/* Tattach, Tauth */
	        char	*aname;		/* Tattach, Tauth */
        
        
	        u32int	perm;		/* Tcreate */ 
	        char	*name;		/* Tcreate */
	        uchar	mode;		/* Tcreate, Topen */
	        char	*extension;	/* Tcreate, twstat */
        
	        u32int	newfid;		/* Twalk */
	        ushort	nwname;		/* Twalk */
	        char	*wname[MAXWELEM];	/* Twalk */
        
	        ushort	nwqid;		/* Rwalk */
	        Qid	wqid[MAXWELEM];		/* Rwalk */
        
	        vlong	offset;		/* Tread, Twrite */
	        u32int	count;		/* Tread, Twrite, Rread */
	        char	*data;		/* Twrite, Rread */
        
	        ushort	nstat;		/* Twstat, Rstat */
	        uchar	*stat;		/* Twstat, Rstat */
        
	        u32int	afid;		/* Tauth, Tattach */
	        Qid aqid;		/* Rauth */

                u32int	n_uname;	/* Tattach, Terror, Tauth */

                Fcall( void )
                : type(0), fid(0), tag(0), msize(0), version(NULL), oldtag(0), ename(NULL), iounit(0),
	          uname(NULL), aname(NULL), perm(0), name(NULL), mode(0), extension(NULL), newfid(0),
	          nwname(0), wname(), nwqid(0), offset(0), count(0), data(NULL), nstat(0),
	          stat(NULL), afid(0), n_uname(0)
                {}

                ~Fcall( void )
                {
                    type = 0;
                }
        } Fcall;

        enum
        {
	        Tversion =	100,
	        Rversion,
	        Tauth =		102,
	        Rauth,
	        Tattach =	104,
	        Rattach,
	        Terror =	106,	/* illegal */
	        Rerror,
	        Tflush =	108,
	        Rflush,
	        Twalk =		110,
	        Rwalk,
	        Topen =		112,
	        Ropen,
	        Tcreate =	114,
	        Rcreate,
	        Tread =		116,
	        Rread,
	        Twrite =	118,
	        Rwrite,
	        Tclunk =	120,
	        Rclunk,
	        Tremove =	122,
	        Rremove,
	        Tstat =		124,
	        Rstat,
	        Twstat =	126,
	        Rwstat,
	        Tmax
        };

        enum
        {
                oldTnop =               50,
                oldRnop,
                oldTosession =  52,     /* illegal */
                oldRosession,           /* illegal */
                oldTerror =     54,     /* illegal */
                oldRerror,
                oldTflush =     56,
                oldRflush,
                oldToattach =   58,     /* illegal */
                oldRoattach,            /* illegal */
                oldTclone =     60,
                oldRclone,
                oldTwalk =              62,
                oldRwalk,
                oldTopen =              64,
                oldRopen,
                oldTcreate =    66,
                oldRcreate,
                oldTread =              68,
                oldRread,
                oldTwrite =     70,
                oldRwrite,
                oldTclunk =     72,
                oldRclunk,
                oldTremove =    74,
                oldRremove,
                oldTstat =              76,
                oldRstat,
                oldTwstat =     78,
                oldRwstat,
                oldTclwalk =    80,
                oldRclwalk,
                oldTauth =              82,     /* illegal */
                oldRauth,                       /* illegal */
                oldTsession =   84,
                oldRsession,
                oldTattach =    86,
                oldRattach,
                oldTmax
        };


        uint	convM2S(uchar*, uint, Fcall*);
        uint	convS2M(Fcall*, uchar*, uint);
        
        int	statcheck(uchar *abuf, uint nbuf);
        uint	convM2D(uchar*, uint, Plan9::Common::Dir*, char*);
        uint	convD2M(Plan9::Common::Dir*, uchar*, uint);
        uint	sizeD2M(Plan9::Common::Dir*);
        
        int	fcallconv(va_list*, Plan9::Conversion::Fconv*);
        int	dirconv(va_list*, Plan9::Conversion::Fconv*);
        int	dirmodeconv(va_list*, Plan9::Conversion::Fconv*);
        void	fdirconv(char *buf, Dir *d);
        
        int	read9pmsg(int, void*, uint);

        uint    dumpsome(char*, char*, long);
        char   *qidtype(char*, uchar);

        uint    convM2Dold(uchar*, uint, Plan9::Common::Dir*, char*);
        uint    convD2Mold(Plan9::Common::Dir*, uchar*, uint);
        uint    sizeD2Mold(Plan9::Common::Dir*);
        uint    convM2Sold(uchar*, uint, Fcall*);
        uint    convS2Mold(Fcall*, uchar*, uint);
        uint    oldhdrsize(uchar);
        uint    iosize(uchar*);

        uchar*  gstring(uchar *p, uchar *ep, char **s);
        uchar*  gqid(uchar *p, uchar *ep, Qid *q);
        uchar* pstring(uchar *p, char *s);
        uchar*  pqid(uchar *p, Qid *q);
        uint    stringsz(char *s);
        uint    sizeS2Mold(Fcall *f);
        uint    sizeS2M(Fcall *f);

        void    rwx(long m, char *s);
        
        enum {
	        NOFID = 0xFFFFFFFF,
        };

    } // Namespace Fcall
}  // Namespace Plan9
        
#endif // __P9FCALL_H_
