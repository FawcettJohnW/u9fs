#include "Fcall.h"
#include "Logging.h"

#define	QIDFMT	"(%.16llux %lud %s)"

using namespace Plan9;
using namespace Plan9::Common;
using namespace Plan9::Conversion;
using namespace Plan9::Fcalls;

int
Plan9::Fcalls::fcallconv(va_list *arg, Fconv *f1)
{
	Fcall *f;
	int fid, type, tag, n, i;
	char buf[512], tmp[200];
	Dir *d;
	Plan9::Common::Qid *q;

	f = va_arg(*arg, Fcall*);
	type = f->type;
	fid = f->fid;
	tag = f->tag;
	switch(type){
	case Tversion:	/* 100 */
		Logging::sprint(buf, "Tversion tag %ud msize %ud version '%s'", tag, f->msize, f->version);
		break;
	case Rversion:
		Logging::sprint(buf, "Rversion tag %ud msize %ud version '%s'", tag, f->msize, f->version);
		break;
	case Tauth:	/* 102 */
		Logging::sprint(buf, "Tauth tag %ud afid %d uname %s aname %s", tag,
			f->afid, f->uname, f->aname);
		break;
	case Rauth:
		Logging::sprint(buf, "Rauth tag %ud qid " QIDFMT, tag,
			f->aqid.path, f->aqid.vers, qidtype(tmp, f->aqid.type));
		break;
	case Tattach:	/* 104 */
		Logging::sprint(buf, "Tattach tag %ud fid %d afid %d uname %s aname %s", tag,
			fid, f->afid, f->uname, f->aname);
		break;
	case Rattach:
		Logging::sprint(buf, "Rattach tag %ud qid " QIDFMT, tag,
			f->qid.path, f->qid.vers, qidtype(tmp, f->qid.type));
		break;
	case Rerror:	/* 107; 106 (Terror) illegal */
		Logging::sprint(buf, "Rerror tag %ud ename %s", tag, f->ename);
		break;
	case Tflush:	/* 108 */
		Logging::sprint(buf, "Tflush tag %ud oldtag %ud", tag, f->oldtag);
		break;
	case Rflush:
		Logging::sprint(buf, "Rflush tag %ud", tag);
		break;
	case Twalk:	/* 110 */
		n = Logging::sprint(buf, "Twalk tag %ud fid %d newfid %d nwname %d ", tag, fid, f->newfid, f->nwname);
			for(i=0; i<f->nwname; i++)
				n += Logging::sprint(buf+n, "%d:%s ", i, f->wname[i]);
		break;
	case Rwalk:
		n = Logging::sprint(buf, "Rwalk tag %ud nwqid %ud ", tag, f->nwqid);
		for(i=0; i<f->nwqid; i++){
			q = &f->wqid[i];
			n += Logging::sprint(buf+n, "%d:" QIDFMT " ", i,
				q->path, q->vers, qidtype(tmp, q->type));
		}
		break;
	case Topen:	/* 112 */
		Logging::sprint(buf, "Topen tag %ud fid %ud mode %d", tag, fid, f->mode);
		break;
	case Ropen:
		Logging::sprint(buf, "Ropen tag %ud qid " QIDFMT " iounit %ud ", tag,
			f->qid.path, f->qid.vers, qidtype(tmp, f->qid.type), f->iounit);
		break;
	case Tcreate:	/* 114 */
		Logging::sprint(buf, "Tcreate tag %ud fid %ud perm %M mode %d", tag, fid, (ulong)f->perm, f->mode);
		break;
	case Rcreate:
		Logging::sprint(buf, "Rcreate tag %ud qid " QIDFMT " iounit %ud ", tag,
			f->qid.path, f->qid.vers, qidtype(tmp, f->qid.type), f->iounit);
		break;
	case Tread:	/* 116 */
		Logging::sprint(buf, "Tread tag %ud fid %d offset %lld count %ud",
			tag, fid, f->offset, f->count);
		break;
	case Rread:
		n = Logging::sprint(buf, "Rread tag %ud count %ud ", tag, f->count);
			dumpsome(buf+n, f->data, f->count);
		break;
	case Twrite:	/* 118 */
		n = Logging::sprint(buf, "Twrite tag %ud fid %d offset %lld count %ud ",
			tag, fid, f->offset, f->count);
		dumpsome(buf+n, f->data, f->count);
		break;
	case Rwrite:
		Logging::sprint(buf, "Rwrite tag %ud count %ud", tag, f->count);
		break;
	case Tclunk:	/* 120 */
		Logging::sprint(buf, "Tclunk tag %ud fid %ud", tag, fid);
		break;
	case Rclunk:
		Logging::sprint(buf, "Rclunk tag %ud", tag);
		break;
	case Tremove:	/* 122 */
		Logging::sprint(buf, "Tremove tag %ud fid %ud", tag, fid);
		break;
	case Rremove:
		Logging::sprint(buf, "Rremove tag %ud", tag);
		break;
	case Tstat:	/* 124 */
		Logging::sprint(buf, "Tstat tag %ud fid %ud", tag, fid);
		break;
	case Rstat:
		n = Logging::sprint(buf, "Rstat tag %ud ", tag);
		if(f->nstat > sizeof tmp)
			Logging::sprint(buf+n, " stat(%d bytes)", f->nstat);
		else{
			d = (Dir*)tmp;
			(old9p?convM2Dold:convM2D)(f->stat, f->nstat, d, (char*)(d+1));
			Logging::sprint(buf+n, " stat ");
			fdirconv(buf+n+6, d);
		}
		break;
	case Twstat:	/* 126 */
		n = Logging::sprint(buf, "Twstat tag %ud fid %ud", tag, fid);
		if(f->nstat > sizeof tmp)
			Logging::sprint(buf+n, " stat(%d bytes)", f->nstat);
		else{
			d = (Dir*)tmp;
			(old9p?convM2Dold:convM2D)(f->stat, f->nstat, d, (char*)(d+1));
			Logging::sprint(buf+n, " stat ");
			fdirconv(buf+n+6, d);
		}
		break;
	case Rwstat:
		Logging::sprint(buf, "Rwstat tag %ud", tag);
		break;
	default:
		Logging::sprint(buf,  "unknown type %d", type);
	}
	Plan9::Conversion::strconv(buf, f1);
	return(sizeof(Fcall*));
}

char*
Plan9::Fcalls::qidtype(char *s, uchar t)
{
	char *p;

	p = s;
	if(t & QTDIR)
		*p++ = 'd';
	if(t & QTAPPEND)
		*p++ = 'a';
	if(t & QTEXCL)
		*p++ = 'l';
	if(t & QTMOUNT)
		*p++ = 'm';
	if(t & QTAUTH)
		*p++ = 'A';
	*p = '\0';
	return s;
}

int
Plan9::Fcalls::dirconv(va_list *arg, Fconv *f)
{
	char buf[160];

	fdirconv(buf, va_arg(*arg, Dir*));
	Plan9::Conversion::strconv(buf, f);
	return(sizeof(Dir*));
}

void
Plan9::Fcalls::fdirconv(char *buf, Dir *d)
{
	char tmp[16];

	Logging::sprint(buf, "'%s' '%s' '%s' '%s' "
		"q " QIDFMT " m %#luo "
		"at %ld mt %ld l %lld "
		"t %d d %d",
			d->name, d->uid, d->gid, d->muid,
			d->qid.path, d->qid.vers, qidtype(tmp, d->qid.type), d->mode,
			d->atime, d->mtime, d->length,
			d->type, d->dev);
}

/*
 * dump out count (or DUMPL, if count is bigger) bytes from
 * buf to ans, as a string if they are all printable,
 * else as a series of hex bytes
 */
#define DUMPL 64

uint
Plan9::Fcalls::dumpsome(char *ans, char *buf, long count)
{
	int i, printable;
	char *p;

	printable = 1;
	if(count > DUMPL)
		count = DUMPL;
	for(i=0; i<count && printable; i++)
		if((buf[i]<32 && buf[i] !='\n' && buf[i] !='\t') || (uchar)buf[i]>127)
			printable = 0;
	p = ans;
	*p++ = '\'';
	if(printable){
		memmove(p, buf, count);
		p += count;
	}else{
		for(i=0; i<count; i++){
			if(i>0 && i%4==0)
				*p++ = ' ';
			Logging::sprint(p, "%2.2ux", (uchar)buf[i]);
			p += 2;
		}
	}
	*p++ = '\'';
	*p = 0;
	return p - ans;
}

uint
Plan9::Fcalls::sizeD2M(Dir *d)
{
	char *sv[5];
	int i, ns;

	sv[0] = d->name;
	sv[1] = d->uid;
	sv[2] = d->gid;
	sv[3] = d->muid;
	sv[4] = d->extension;

	ns = 0;
	for(i = 0; i < 5; i++)
		ns += strlen(sv[i]);

	return STATFIXLEN + ns;
}

uint
Plan9::Fcalls::convD2M(Dir *d, uchar *buf, uint nbuf)
{
	uchar *p, *ebuf;
	char *sv[5];
	int i, ns, nsv[5], ss;

	if(nbuf < BIT16SZ)
		return 0;

	p = buf;
	ebuf = buf + nbuf;

	sv[0] = d->name;
	sv[1] = d->uid;
	sv[2] = d->gid;
	sv[3] = d->muid;
	sv[4] = d->extension;

	ns = 0;
	for(i = 0; i < 5; i++){
		nsv[i] = strlen(sv[i]);
		ns += nsv[i];
	}

	ss = STATFIXLEN + ns;

	/* set size befor erroring, so user can know how much is needed */
	/* note that length excludes count field itself */
	PBIT16(p, ss-BIT16SZ);
	p += BIT16SZ;

	if(ss > nbuf)
		return BIT16SZ;

	PBIT16(p, d->type);
	p += BIT16SZ;
	PBIT32(p, d->dev);
	p += BIT32SZ;
	PBIT8(p, d->qid.type);
	p += BIT8SZ;
	PBIT32(p, d->qid.vers);
	p += BIT32SZ;
	PBIT64(p, d->qid.path);
	p += BIT64SZ;
	PBIT32(p, d->mode);
	p += BIT32SZ;
	PBIT32(p, d->atime);
	p += BIT32SZ;
	PBIT32(p, d->mtime);
	p += BIT32SZ;
	PBIT64(p, d->length);
	p += BIT64SZ;

	for(i = 0; i < 5; i++){
		ns = nsv[i];
		if(p + ns + BIT16SZ > ebuf)
			return 0;
		PBIT16(p, ns);
		p += BIT16SZ;
		memmove(p, sv[i], ns);
		p += ns;
	}

	PBIT32(p, d->n_uid);
	p += BIT32SZ;
	PBIT32(p, d->n_gid);
	p += BIT32SZ;
	PBIT32(p, d->n_muid);
	p += BIT32SZ;

/*
        if (d->extension)
        {
            // Symlink name was allocated in fidstat() 
            free(d->extension);
        }
*/

	if(ss != p - buf)
		return 0;

	return p - buf;
}

int
Plan9::Fcalls::statcheck(uchar *buf, uint nbuf)
{
	uchar *ebuf;
	int i;

	ebuf = buf + nbuf;

	buf += STATFIXLEN - 4 * BIT16SZ;

	for(i = 0; i < 4; i++){
		if(buf + BIT16SZ > ebuf)
			return -1;
		buf += BIT16SZ + GBIT16(buf);
	}

	if(buf != ebuf)
		return -1;

	return 0;
}

static char nullstring[] = "";

uint
Plan9::Fcalls::convM2D(uchar *buf, uint nbuf, Dir *d, char *strs)
{
	uchar *p, *ebuf;
	char *sv[5];
	int i, ns;

	p = buf;
	ebuf = buf + nbuf;

	p += BIT16SZ;	/* ignore size */
	d->type = GBIT16(p);
	p += BIT16SZ;
	d->dev = GBIT32(p);
	p += BIT32SZ;
	d->qid.type = GBIT8(p);
	p += BIT8SZ;
	d->qid.vers = GBIT32(p);
	p += BIT32SZ;
	d->qid.path = GBIT64(p);
	p += BIT64SZ;
	d->mode = GBIT32(p);
	p += BIT32SZ;
	d->atime = GBIT32(p);
	p += BIT32SZ;
	d->mtime = GBIT32(p);
	p += BIT32SZ;
	d->length = GBIT64(p);
	p += BIT64SZ;

	d->name = NULL;
	d->uid = NULL;
	d->gid = NULL;
	d->muid = NULL;

	for(i = 0; i < 5; i++){
		if(p + BIT16SZ > ebuf)
			return 0;
		ns = GBIT16(p);
		p += BIT16SZ;
		if(p + ns > ebuf)
			return 0;
		if(strs){
			sv[i] = strs;
			memmove(strs, p, ns);
			strs += ns;
			*strs++ = '\0';
		}
		p += ns;
	}

	if(strs){
		d->name = sv[0];
		d->uid = sv[1];
		d->gid = sv[2];
		d->muid = sv[3];
		d->extension = sv[4];
	}else{
		d->name = nullstring;
		d->uid = nullstring;
		d->gid = nullstring;
		d->muid = nullstring;
		d->extension = nullstring;
	}
	
	d->n_uid = GBIT32(p);
	p += BIT64SZ;
	d->n_gid = GBIT32(p);
	p += BIT64SZ;
	d->n_muid = GBIT32(p);

	return p - buf;
}

uchar*
Plan9::Fcalls::gstring(uchar *p, uchar *ep, char **s)
{
	uint n;

	if(p+BIT16SZ > ep)
		return NULL;
	n = GBIT16(p);
	p += BIT16SZ - 1;
	if(p+n+1 > ep)
		return NULL;
	/* move it down, on top of count, to make room for '\0' */
	memmove(p, p + 1, n);
	p[n] = '\0';
	*s = (char*)p;
	p += n+1;
	return p;
}

uchar*
Plan9::Fcalls::gqid(uchar *p, uchar *ep, Qid *q)
{
	if(p+QIDSZ > ep)
		return NULL;
	q->type = GBIT8(p);
	p += BIT8SZ;
	q->vers = GBIT32(p);
	p += BIT32SZ;
	q->path = GBIT64(p);
	p += BIT64SZ;
	return p;
}

/*
 * no syntactic checks.
 * three causes for error:
 *  1. message size field is incorrect
 *  2. input buffer too short for its own data (counts too long, etc.)
 *  3. too many names or qids
 * gqid() and gstring() return NULL if they would reach beyond buffer.
 * main switch statement checks range and also can fall through
 * to test at end of routine.
 */
uint
Plan9::Fcalls::convM2S(uchar *ap, uint nap, Fcall *f)
{
	uchar *p, *ep;
	uint i, size;

	p = ap;
	ep = p + nap;

Logging::fprint(2, "Checkpoint 1\n");
	if(p+BIT32SZ+BIT8SZ+BIT16SZ > ep)
		return 0;
	size = GBIT32(p);
	p += BIT32SZ;

Logging::fprint(2, "Checkpoint 2\n");
	if(size > nap)
		return 0;
	if(size < BIT32SZ+BIT8SZ+BIT16SZ)
		return 0;

Logging::fprint(2, "Checkpoint 3\n");
	f->type = GBIT8(p);
	p += BIT8SZ;
	f->tag = GBIT16(p);
	p += BIT16SZ;

Logging::fprint(2, "Checkpoint 4\n");
	switch(f->type)
	{
	default:
		return 0;

	case Tversion:
Logging::fprint(2, "Case Tversion\n");
		if(p+BIT32SZ > ep)
			return 0;
		f->msize = GBIT32(p);
		p += BIT32SZ;
		p = gstring(p, ep, &f->version);
		break;

/*
	case Tsession:
		if(p+BIT16SZ > ep)
			return 0;
		f->nchal = GBIT16(p);
		p += BIT16SZ;
		if(p+f->nchal > ep)
			return 0;
		f->chal = p;
		p += f->nchal;
		break;
*/

	case Tflush:
Logging::fprint(2, "Case Tflush\n");
		if(p+BIT16SZ > ep)
			return 0;
		f->oldtag = GBIT16(p);
		p += BIT16SZ;
		break;

	case Tauth:
Logging::fprint(2, "Case Tauth\n");
		if(p+BIT32SZ > ep)
			return 0;
		f->afid = GBIT32(p);
		p += BIT32SZ;
		p = gstring(p, ep, &f->uname);
		if(p == NULL)
			break;
		p = gstring(p, ep, &f->aname);
		if(p == NULL)
			break;
		f->n_uname = GBIT32(p);
Logging::fprint(2, "     f->n_uname = %d\n", f->n_uname);
		p += BIT32SZ;
		break;

/*
b
	case Tattach:
		if(p+BIT32SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		p = gstring(p, ep, &f->uname);
		if(p == NULL)
			break;
		p = gstring(p, ep, &f->aname);
		if(p == NULL)
			break;
		if(p+BIT16SZ > ep)
			return 0;
		f->nauth = GBIT16(p);
		p += BIT16SZ;
		if(p+f->nauth > ep)
			return 0;
		f->auth = p;
		p += f->nauth;
		break;
*/

	case Tattach:
Logging::fprint(2, "Case Tattach\n");
		if(p+BIT32SZ > ep)
			return 0;
		f->fid = GBIT32(p);
Logging::fprint(2, "     f->fid = %d\n", f->fid);
		p += BIT32SZ;
		if(p+BIT32SZ > ep)
			return 0;
		f->afid = GBIT32(p);
Logging::fprint(2, "     f->afid = %d\n", f->afid);
		p += BIT32SZ;
		p = gstring(p, ep, &f->uname);
		if(p == NULL)
                {
Logging::fprint(2, "     FAILED getting f->unames\n");
			break;
                }
Logging::fprint(2, "     f->uname = %s\n", f->uname);
		p = gstring(p, ep, &f->aname);
		if(p == NULL)
                {
Logging::fprint(2, "     FAILED getting f->aname\n");
			break;
                }
Logging::fprint(2, "     f->aname = %s\n", f->aname);
		if(p+BIT32SZ > ep)
                {
Logging::fprint(2, "     Went past end of buffer\n");
			return 0;
                }
		f->n_uname = GBIT32(p);
Logging::fprint(2, "     f->n_uname = %d\n", f->n_uname);
		p += BIT32SZ;
		break;


	case Twalk:
Logging::fprint(2, "Case Twalk\n");
		if(p+BIT32SZ+BIT32SZ+BIT16SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		f->newfid = GBIT32(p);
		p += BIT32SZ;
		f->nwname = GBIT16(p);
		p += BIT16SZ;
		if(f->nwname > MAXWELEM)
			return 0;
Logging::fprint(2, "Twalk request came in.  f->nwname = %d\n", f->nwname);
		for(i=0; i<f->nwname; i++){
			p = gstring(p, ep, &f->wname[i]);
			if(p == NULL)
				break;
Logging::fprint(2, "                        f->wname[%d] = %s\n", i, f->wname[i]);
		}
		break;

	case Topen:
Logging::fprint(2, "Case Topen\n");
		if(p+BIT32SZ+BIT8SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		f->mode = GBIT8(p);
		p += BIT8SZ;
		break;

	case Tcreate:
Logging::fprint(2, "Case Tcreate\n");
		if(p+BIT32SZ+BIT32SZ+BIT8SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		p = gstring(p, ep, &f->name);
		if(p == NULL)
			break;
		f->perm = GBIT32(p);
		p += BIT32SZ;
		f->mode = GBIT8(p);
		p += BIT8SZ;
		p = gstring(p, ep, &f->extension);
Logging::fprint(2, "Attempting to create file %s, mode %o, permissions 0x%x\n", f->name, f->mode, f->perm);
		break;

	case Tread:
Logging::fprint(2, "Case Tread\n");
		if(p+BIT32SZ+BIT64SZ+BIT32SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		f->offset = GBIT64(p);
		p += BIT64SZ;
		f->count = GBIT32(p);
		p += BIT32SZ;
		break;

	case Twrite:
Logging::fprint(2, "Case Twrite\n");
		if(p+BIT32SZ+BIT64SZ+BIT32SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		f->offset = GBIT64(p);
		p += BIT64SZ;
		f->count = GBIT32(p);
		p += BIT32SZ;
		if(p+f->count > ep)
			return 0;
		f->data = (char*)p;
		p += f->count;
		break;

	case Tclunk:
Logging::fprint(2, "Case Tclunk\n");
	case Tremove:
Logging::fprint(2, "Case Tremove\n");
		if(p+BIT32SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		break;

	case Tstat:
Logging::fprint(2, "Case Tstat\n");
		if(p+BIT32SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		break;

	case Twstat:
Logging::fprint(2, "Case Twstat\n");
		if(p+BIT32SZ+BIT16SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		f->nstat = GBIT16(p);
		p += BIT16SZ;
		if(p+f->nstat > ep)
			return 0;
		f->stat = p;
		p += f->nstat;
		break;

/*
 */
	case Rversion:
Logging::fprint(2, "Case Rversion\n");
		if(p+BIT32SZ > ep)
			return 0;
		f->msize = GBIT32(p);
		p += BIT32SZ;
		p = gstring(p, ep, &f->version);
		break;

/*
	case Rsession:
		if(p+BIT16SZ > ep)
			return 0;
		f->nchal = GBIT16(p);
		p += BIT16SZ;
		if(p+f->nchal > ep)
			return 0;
		f->chal = p;
		p += f->nchal;
		p = gstring(p, ep, &f->authid);
		if(p == NULL)
			break;
		p = gstring(p, ep, &f->authdom);
		break;
*/

	case Rerror:
Logging::fprint(2, "Case Rerror\n");
		p = gstring(p, ep, &f->ename);
Logging::fprint(2, "     f->ename = %s\n", f->ename);
		f->n_uname = GBIT32(p);
Logging::fprint(2, "     f->n_uname = %d\n", f->n_uname);
		p += BIT32SZ;
		break;

	case Rflush:
Logging::fprint(2, "Case Rflush\n");
		break;

/*
	case Rattach:
		p = gqid(p, ep, &f->qid);
		if(p == NULL)
			break;
		if(p+BIT16SZ > ep)
			return 0;
		f->nrauth = GBIT16(p);
		p += BIT16SZ;
		if(p+f->nrauth > ep)
			return 0;
		f->rauth = p;
		p += f->nrauth;
		break;
*/

	case Rattach:
Logging::fprint(2, "Case Rattach\n");
		p = gqid(p, ep, &f->qid);
		if(p == NULL)
			break;
		break;


	case Rwalk:
Logging::fprint(2, "Case Rwalk\n");
		if(p+BIT16SZ > ep)
			return 0;
		f->nwqid = GBIT16(p);
		p += BIT16SZ;
		if(f->nwqid > MAXWELEM)
			return 0;
		for(i=0; i<f->nwqid; i++){
			p = gqid(p, ep, &f->wqid[i]);
			if(p == NULL)
				break;
		}
		break;

	case Ropen:
Logging::fprint(2, "Case Ropen\n");
	case Rcreate:
Logging::fprint(2, "Case Rcreate\n");
		p = gqid(p, ep, &f->qid);
		if(p == NULL)
			break;
		if(p+BIT32SZ > ep)
			return 0;
		f->iounit = GBIT32(p);
		p += BIT32SZ;
		break;

	case Rread:
Logging::fprint(2, "Case Rread\n");
		if(p+BIT32SZ > ep)
			return 0;
		f->count = GBIT32(p);
Logging::fprint(2, "   f->count is %d\n", f->count);
		p += BIT32SZ;
		if(p+f->count > ep)
			return 0;
		f->data = (char*)p;
		p += f->count;
		break;

	case Rwrite:
Logging::fprint(2, "Case Rwrote\n");
		if(p+BIT32SZ > ep)
			return 0;
		f->count = GBIT32(p);
		p += BIT32SZ;
		break;

	case Rclunk:
Logging::fprint(2, "Case Rclunk\n");
	case Rremove:
Logging::fprint(2, "Case Rremove\n");
		break;

	case Rstat:
Logging::fprint(2, "Case Rstat\n");
		if(p+BIT16SZ > ep)
			return 0;
		f->nstat = GBIT16(p);
		p += BIT16SZ;
		if(p+f->nstat > ep)
			return 0;
		f->stat = p;
		p += f->nstat;
		break;

	case Rwstat:
Logging::fprint(2, "Case Rwstat\n");
		break;
	}

	if(p==NULL || p>ep)
        {
if (p == NULL)
Logging::fprint(2, "Returning 0 because p was NULL\n");
else
Logging::fprint(2, "Returning 0 because p > ep\n");
		return 0;
        }

Logging::fprint(2, "size = %d\n", size);
	if(ap+size == p)
        {
Logging::fprint(2, "Returning size = %d\n", size);
		return size;
        }

Logging::fprint(2, "Default return 0\n");
	return 0;
}

uchar*
Plan9::Fcalls::pstring(uchar *p, char *s)
{
	uint n;

	n = strlen(s);
	PBIT16(p, n);
	p += BIT16SZ;
	memmove(p, s, n);
	p += n;
	return p;
}

uchar*
Plan9::Fcalls::pqid(uchar *p, Qid *q)
{
	PBIT8(p, q->type);
	p += BIT8SZ;
	PBIT32(p, q->vers);
	p += BIT32SZ;
	PBIT64(p, q->path);
	p += BIT64SZ;
	return p;
}

uint
Plan9::Fcalls::stringsz(char *s)
{
	return BIT16SZ+strlen(s);
}

uint
Plan9::Fcalls::sizeS2M(Fcall *f)
{
	uint n;
	int i;

	n = 0;
	n += BIT32SZ;	/* size */
	n += BIT8SZ;	/* type */
	n += BIT16SZ;	/* tag */

	switch(f->type)
	{
	default:
		return 0;

	case Tversion:
		n += BIT32SZ;
		n += stringsz(f->version);
		break;

/*
	case Tsession:
		n += BIT16SZ;
		n += f->nchal;
		break;
*/

	case Tflush:
		n += BIT16SZ;
		break;

	case Tauth:
		n += BIT32SZ;
		n += stringsz(f->uname);
		n += stringsz(f->aname);
		break;

	case Tattach:
		n += BIT32SZ; /* fid */
		n += BIT32SZ; /* afid */
		n += stringsz(f->uname);
		n += stringsz(f->aname);
		n += BIT32SZ; /* n_uname */
		break;


	case Twalk:
		n += BIT32SZ;
		n += BIT32SZ;
		n += BIT16SZ;
		for(i=0; i<f->nwname; i++)
			n += stringsz(f->wname[i]);
		break;

	case Topen:
		n += BIT32SZ;
		n += BIT8SZ;
		break;

	case Tcreate:
		n += BIT32SZ;
		n += stringsz(f->name);
		n += BIT32SZ;
		n += BIT8SZ;
		break;

	case Tread:
		n += BIT32SZ;
		n += BIT64SZ;
		n += BIT32SZ;
		break;

	case Twrite:
		n += BIT32SZ;
		n += BIT64SZ;
		n += BIT32SZ;
		n += f->count;
		break;

	case Tclunk:
	case Tremove:
		n += BIT32SZ;
		break;

	case Tstat:
		n += BIT32SZ;
		break;

	case Twstat:
		n += BIT32SZ;
		n += BIT16SZ;
		n += f->nstat;
		break;
/*
 */

	case Rversion:
		n += BIT32SZ;
		n += stringsz(f->version);
		break;

/*
	case Rsession:
		n += BIT16SZ;
		n += f->nchal;
		n += stringsz(f->authid);
		n += stringsz(f->authdom);
		break;

*/
	case Rerror:
		n += stringsz(f->ename);
		n += BIT32SZ; /* m_uname */
		break;

	case Rflush:
		break;

	case Rauth:
		n += QIDSZ;
		break;

/*
	case Rattach:
		n += QIDSZ;
		n += BIT16SZ;
		n += f->nrauth;
		break;
*/

	case Rattach:
		n += QIDSZ;
		break;


	case Rwalk:
		n += BIT16SZ;
		n += f->nwqid*QIDSZ;
		break;

	case Ropen:
	case Rcreate:
		n += QIDSZ;
		n += BIT32SZ;
		break;

	case Rread:
		n += BIT32SZ;
		n += f->count;
		break;

	case Rwrite:
		n += BIT32SZ;
		break;

	case Rclunk:
		break;

	case Rremove:
		break;

	case Rstat:
		n += BIT16SZ;
		n += f->nstat;
		break;

	case Rwstat:
		break;
	}
	return n;
}

uint
Plan9::Fcalls::convS2M(Fcall *f, uchar *ap, uint nap)
{
	uchar *p;
	uint i, size;

	size = sizeS2M(f);
	if(size == 0)
		return 0;
	if(size > nap)
		return 0;

	p = (uchar*)ap;

	PBIT32(p, size);
	p += BIT32SZ;
	PBIT8(p, f->type);
	p += BIT8SZ;
	PBIT16(p, f->tag);
	p += BIT16SZ;

	switch(f->type)
	{
	default:
		return 0;

	case Tversion:
		PBIT32(p, f->msize);
		p += BIT32SZ;
		p = pstring(p, f->version);
		break;

/*
	case Tsession:
		PBIT16(p, f->nchal);
		p += BIT16SZ;
		f->chal = p;
		p += f->nchal;
		break;
*/

	case Tflush:
		PBIT16(p, f->oldtag);
		p += BIT16SZ;
		break;

	case Tauth:
		PBIT32(p, f->afid);
		p += BIT32SZ;
		p  = pstring(p, f->uname);
		p  = pstring(p, f->aname);
		PBIT32(p, f->n_uname);
		p += BIT32SZ;
		break;

	case Tattach:
		PBIT32(p, f->fid);
		p += BIT32SZ;
		PBIT32(p, f->afid);
		p += BIT32SZ;
		p  = pstring(p, f->uname);
		p  = pstring(p, f->aname);
		PBIT32(p, f->n_uname);
		p += BIT32SZ;
		break;

	case Twalk:
		PBIT32(p, f->fid);
		p += BIT32SZ;
		PBIT32(p, f->newfid);
		p += BIT32SZ;
		PBIT16(p, f->nwname);
		p += BIT16SZ;
		if(f->nwname > MAXWELEM)
			return 0;
		for(i=0; i<f->nwname; i++)
			p = pstring(p, f->wname[i]);
		break;

	case Topen:
		PBIT32(p, f->fid);
		p += BIT32SZ;
		PBIT8(p, f->mode);
		p += BIT8SZ;
		break;

	case Tcreate:
		PBIT32(p, f->fid);
		p += BIT32SZ;
		p = pstring(p, f->name);
		PBIT32(p, f->perm);
		p += BIT32SZ;
		PBIT8(p, f->mode);
		p += BIT8SZ;
		break;

	case Tread:
		PBIT32(p, f->fid);
		p += BIT32SZ;
		PBIT64(p, f->offset);
		p += BIT64SZ;
		PBIT32(p, f->count);
		p += BIT32SZ;
		break;

	case Twrite:
		PBIT32(p, f->fid);
		p += BIT32SZ;
		PBIT64(p, f->offset);
		p += BIT64SZ;
		PBIT32(p, f->count);
		p += BIT32SZ;
		memmove(p, f->data, f->count);
		p += f->count;
		break;

	case Tclunk:
	case Tremove:
		PBIT32(p, f->fid);
		p += BIT32SZ;
		break;

	case Tstat:
		PBIT32(p, f->fid);
		p += BIT32SZ;
		break;

	case Twstat:
		PBIT32(p, f->fid);
		p += BIT32SZ;
		PBIT16(p, f->nstat);
		p += BIT16SZ;
		memmove(p, f->stat, f->nstat);
		p += f->nstat;
		break;
/*
 */

	case Rversion:
		PBIT32(p, f->msize);
		p += BIT32SZ;
		p = pstring(p, f->version);
		break;

/*
	case Rsession:
		PBIT16(p, f->nchal);
		p += BIT16SZ;
		f->chal = p;
		p += f->nchal;
		p = pstring(p, f->authid);
		p = pstring(p, f->authdom);
		break;
*/

	case Rerror:
		p = pstring(p, f->ename);
		PBIT32(p, f->n_uname);
		p += BIT32SZ;
		break;

	case Rflush:
		break;

	case Rauth:
		p = pqid(p, &f->aqid);
		break;

	case Rattach:
		p = pqid(p, &f->qid);
		break;

	case Rwalk:
		PBIT16(p, f->nwqid);
		p += BIT16SZ;
		if(f->nwqid > MAXWELEM)
			return 0;
		for(i=0; i<f->nwqid; i++)
			p = pqid(p, &f->wqid[i]);
		break;

	case Ropen:
	case Rcreate:
		p = pqid(p, &f->qid);
		PBIT32(p, f->iounit);
		p += BIT32SZ;
		break;

	case Rread:
		PBIT32(p, f->count);
		p += BIT32SZ;
		memmove(p, f->data, f->count);
		p += f->count;
		break;

	case Rwrite:
		PBIT32(p, f->count);
		p += BIT32SZ;
		break;

	case Rclunk:
		break;

	case Rremove:
		break;

	case Rstat:
		PBIT16(p, f->nstat);
		p += BIT16SZ;
		memmove(p, f->stat, f->nstat);
		p += f->nstat;
		break;

	case Rwstat:
		break;
	}
	if(size != p-ap)
		return 0;
	return size;
}

/*
 * routines to package the old protocol in the new structures.
 */
uint
Plan9::Fcalls::oldhdrsize(uchar type)
{
	switch(type){
	default:
		return 0;
	case oldTnop:
		return 3;
	case oldTflush:
		return 3+2;
	case oldTclone:
		return 3+2+2;
	case oldTwalk:
		return 3+2+28;
	case oldTopen:
		return 3+2+1;
	case oldTcreate:
		return 3+2+28+4+1;
	case oldTread:
		return 3+2+8+2;
	case oldTwrite:
		return 3+2+8+2+1;
	case oldTclunk:
		return 3+2;
	case oldTremove:
		return 3+2;
	case oldTstat:
		return 3+2;
	case oldTwstat:
		return 3+2+116;
	case oldTsession:
		return 3+8;
	case oldTattach:
		return 3+2+28+28+72+13;
	}
}

uint
Plan9::Fcalls::iosize(uchar *p)
{
	if(p[0] != oldTwrite)
		return 0;
	return p[3+2+8] | (p[3+2+8+1]<<8);
}

uint
Plan9::Fcalls::sizeS2Mold(Fcall *f)
{
	switch(f->type)
	{
	default:
		abort();
		return 0;

	/* no T messages */

/*
 */
	case Rversion:
		return 1+2;

/*
	case Rsession:
		return 1+2+8+28+48;
*/

	case Rattach:
		return 1+2+2+4+4+13;

	case Rerror:
		return 1+2+64;

	case Rflush:
		if(f->tag&0x8000)
			return 1+2+8+28+48;	/* session */
		return 1+2;

	/* assumes we don't ever see Tclwalk requests ... */
	case Rwalk:
		if(f->nwqid == 0)
			return 1+2+2;
		else
			return 1+2+2+4+4;

	case Ropen:
		return 1+2+2+4+4;

	case Rcreate:
		return 1+2+2+4+4;

	case Rread:
		return 1+2+2+2+1+f->count;

	case Rwrite:
		return 1+2+2+2;

	case Rclunk:
		return 1+2+2;

	case Rremove:
		return 1+2+2;

	case Rstat:
		return 1+2+2+116;

	case Rwstat:
		return 1+2+2;
	}
}

#define SHORT(x)        p[0]=f->x; p[1]=f->x>>8; p += 2
#define LONG(x)         p[0]=f->x; p[1]=f->x>>8; p[2]=f->x>>16; p[3]=f->x>>24; p += 4
#define VLONG(x)        p[0]=f->x;      p[1]=f->x>>8;\
                        p[2]=f->x>>16;  p[3]=f->x>>24;\
                        p[4]=f->x>>32;  p[5]=f->x>>40;\
                        p[6]=f->x>>48;  p[7]=f->x>>56;\
                        p += 8
#define STRING(x,n)     Logging::strecpy((char*)p, (char*)p+n, f->x); p += n;
#define FIXQID(q)               q.path ^= (q.path>>33); q.path &= 0x7FFFFFFF; q.path |= (q.type&0x80)<<24

uint
Plan9::Fcalls::convS2Mold(Fcall *f, uchar *ap, uint nap)
{
	uchar *p;

	if(nap < sizeS2Mold(f))
		return 0;

	p = ap;
	switch(f->type)
	{
	default:
		abort();
		return 0;

	/* no T messages */

/*
 */
	case Rversion:
		*p++ = oldRnop;
		SHORT(tag);
		break;

/*
	case Rsession:
		*p++ = oldRsession;
		SHORT(tag);

		if(f->nchal > 8)
			f->nchal = 8;
		memmove(p, f->chal, f->nchal);
		p += f->nchal;
		if(f->nchal < 8){
			memset(p, 0, 8 - f->nchal);
			p += 8 - f->nchal;
		}

		STRING(authid, 28);
		STRING(authdom, 48);
		break;
*/

	case Rattach:
		*p++ = oldRattach;
		SHORT(tag);
		SHORT(fid);
		FIXQID(f->qid);
		LONG(qid.path);
		LONG(qid.vers);
		memset(p, 0, 13);
		p += 13;
		break;

	case Rerror:
		*p++ = oldRerror;
		SHORT(tag);
		STRING(ename, 64);
		break;

	case Rflush:
		if(f->tag&0x8000){
			*p++ = oldRsession;
			f->tag &= ~0x8000;
			SHORT(tag);
			memset(p, 0, 8+28+48);
			p += 8+28+48;
		}else{
			*p++ = oldRflush;
			SHORT(tag);
		}
		break;

	/* assumes we don't ever see Tclwalk requests ... */
	case Rwalk:
		if(f->nwqid == 0){	/* successful clone */
			*p++ = oldRclone;
			SHORT(tag);
			SHORT(fid);
		}else{			/* successful 1-element walk */
			*p++ = oldRwalk;
			SHORT(tag);
			SHORT(fid);
			FIXQID(f->wqid[0]);
			LONG(wqid[0].path);
			LONG(wqid[0].vers);
		}
		break;

	case Ropen:
		*p++ = oldRopen;
		SHORT(tag);
		SHORT(fid);
		FIXQID(f->qid);
		LONG(qid.path);
		LONG(qid.vers);
		break;

	case Rcreate:
		*p++ = oldRcreate;
		SHORT(tag);
		SHORT(fid);
		FIXQID(f->qid);
		LONG(qid.path);
		LONG(qid.vers);
		break;

	case Rread:
		*p++ = oldRread;
		SHORT(tag);
		SHORT(fid);
		SHORT(count);
		p++;	/* pad(1) */
		memmove(p, f->data, f->count);
		p += f->count;
		break;

	case Rwrite:
		*p++ = oldRwrite;
		SHORT(tag);
		SHORT(fid);
		SHORT(count);
		break;

	case Rclunk:
		*p++ = oldRclunk;
		SHORT(tag);
		SHORT(fid);
		break;

	case Rremove:
		*p++ = oldRremove;
		SHORT(tag);
		SHORT(fid);
		break;

	case Rstat:
		*p++ = oldRstat;
		SHORT(tag);
		SHORT(fid);
		memmove(p, f->stat, 116);
		p += 116;
		break;

	case Rwstat:
		*p++ = oldRwstat;
		SHORT(tag);
		SHORT(fid);
		break;
	}
	return p - ap;
}

uint
Plan9::Fcalls::sizeD2Mold(Dir *d)
{
	return 116;
}

uint
Plan9::Fcalls::convD2Mold(Dir *f, uchar *ap, uint nap)
{
	uchar *p;

	if(nap < 116)
		return 0;

	p = ap;
	STRING(name, 28);
	STRING(uid, 28);
	STRING(gid, 28);
	FIXQID(f->qid);
	LONG(qid.path);
	LONG(qid.vers);
	LONG(mode);
	LONG(atime);
	LONG(mtime);
	VLONG(length);
	SHORT(type);
	SHORT(dev);

	return p - ap;
}

#undef SHORT
#undef LONG
#undef VLONG
#undef STRING
#define	CHAR(x)	f->x = *p++
#define	SHORT(x)	f->x = (p[0] | (p[1]<<8)); p += 2
#define	LONG(x)		f->x = (p[0] | (p[1]<<8) |\
				(p[2]<<16) | (p[3]<<24)); p += 4
#define	VLONG(x)	f->x = (ulong)(p[0] | (p[1]<<8) |\
					(p[2]<<16) | (p[3]<<24)) |\
				((vlong)(p[4] | (p[5]<<8) |\
					(p[6]<<16) | (p[7]<<24)) << 32); p += 8
#define	STRING(x,n)	f->x = (char*)p; p += n

uint
Plan9::Fcalls::convM2Sold(uchar *ap, uint nap, Fcall *f)
{
	uchar *p, *q, *ep;

	p = ap;
	ep = p + nap;

	if(p+3 > ep)
		return 0;

        static char oldVersion[]="9P1";
	switch(*p++){
	case oldTnop:
		f->type = Tversion;
		SHORT(tag);
		f->msize = 0;
		f->version = oldVersion;
		break;

	case oldTflush:
		f->type = Tflush;
		SHORT(tag);
		if(p+2 > ep)
			return 0;
		SHORT(oldtag);
		break;

	case oldTclone:
		f->type = Twalk;
		SHORT(tag);
		if(p+2+2 > ep)
			return 0;
		SHORT(fid);
		SHORT(newfid);
		f->nwname = 0;
		break;

	case oldTwalk:
		f->type = Twalk;
		SHORT(tag);
		if(p+2+28 > ep)
			return 0;
		SHORT(fid);
		f->newfid = f->fid;
		f->nwname = 1;
		f->wname[0] = (char*)p;
		p += 28;
		break;

	case oldTopen:
		f->type = Topen;
		SHORT(tag);
		if(p+2+1 > ep)
			return 0;
		SHORT(fid);
		CHAR(mode);
		break;

	case oldTcreate:
		f->type = Tcreate;
		SHORT(tag);
		if(p+2+28+4+1 > ep)
			return 0;
		SHORT(fid);
		f->name = (char*)p;
		p += 28;
		LONG(perm);
		CHAR(mode);
		break;

	case oldTread:
		f->type = Tread;
		SHORT(tag);
		if(p+2+8+2 > ep)
			return 0;
		SHORT(fid);
		VLONG(offset);
		SHORT(count);
		break;

	case oldTwrite:
		f->type = Twrite;
		SHORT(tag);
		if(p+2+8+2+1 > ep)
			return 0;
		SHORT(fid);
		VLONG(offset);
		SHORT(count);
		p++;	/* pad(1) */
		if(p+f->count > ep)
			return 0;
		f->data = (char*)p;
		p += f->count;
		break;

	case oldTclunk:
		f->type = Tclunk;
		SHORT(tag);
		if(p+2 > ep)
			return 0;
		SHORT(fid);
		break;

	case oldTremove:
		f->type = Tremove;
		SHORT(tag);
		if(p+2 > ep)
			return 0;
		SHORT(fid);
		break;

	case oldTstat:
		f->type = Tstat;
		f->nstat = 116;
		SHORT(tag);
		if(p+2 > ep)
			return 0;
		SHORT(fid);
		break;

	case oldTwstat:
		f->type = Twstat;
		SHORT(tag);
		if(p+2+116 > ep)
			return 0;
		SHORT(fid);
		f->stat = p;
		q = p+28*3+5*4;
		memset(q, 0xFF, 8);	/* clear length to ``don't care'' */
		p += 116;
		break;

/*
	case oldTsession:
		f->type = Tsession;
		SHORT(tag);
		if(p+8 > ep)
			return 0;
		f->chal = p;
		p += 8;
		f->nchal = 8;
		break;
*/
	case oldTsession:
		f->type = Tflush;
		SHORT(tag);
		f->tag |= 0x8000;
		f->oldtag = f->tag;
		p += 8;
		break;

	case oldTattach:
		f->type = Tattach;
		SHORT(tag);
		if(p+2+28+28+72+13 > ep)
			return 0;
		SHORT(fid);
		STRING(uname, 28);
		STRING(aname, 28);
		p += 72+13;
		f->afid = NOFID;
		break;

	default:
		return 0;
	}

	return p-ap;
}

uint
Plan9::Fcalls::convM2Dold(uchar *ap, uint nap, Dir *f, char *strs)
{
	uchar *p;

	USED(strs);

	if(nap < 116)
		return 0;

	p = (uchar*)ap;
	STRING(name, 28);
	STRING(uid, 28);
	STRING(gid, 28);
	LONG(qid.path);
	LONG(qid.vers);
	LONG(mode);
	LONG(atime);
	LONG(mtime);
	VLONG(length);
	SHORT(type);
	SHORT(dev);
	f->qid.type = (f->mode>>24)&0xF0;
	return p - (uchar*)ap;
}

static const char *modes[] =
{
	"---",
	"--x",
	"-w-",
	"-wx",
	"r--",
	"r-x",
	"rw-",
	"rwx",
};

void
Plan9::Fcalls::rwx(long m, char *s)
{
	strncpy(s, modes[m], 3);
}

int
Plan9::Fcalls::dirmodeconv(va_list *arg, Fconv *f)
{
	static char buf[16];
	ulong m;

	m = va_arg(*arg, ulong);

	if(m & DMDIR)
		buf[0]='d';
	else if(m & DMAPPEND)
		buf[0]='a';
	else
		buf[0]='-';
	if(m & DMEXCL)
		buf[1]='l';
	else
		buf[1]='-';
	rwx((m>>6)&7, buf+2);
	rwx((m>>3)&7, buf+5);
	rwx((m>>0)&7, buf+8);
	buf[11] = 0;

	strconv(buf, f);
	return 0;
}
