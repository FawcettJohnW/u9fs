#include	<plan9.h>
#include	<fcall.h>

static
uchar*
gstring(uchar *p, uchar *ep, char **s)
{
	uint n;

	if(p+BIT16SZ > ep)
		return nil;
	n = GBIT16(p);
	p += BIT16SZ - 1;
	if(p+n+1 > ep)
		return nil;
	/* move it down, on top of count, to make room for '\0' */
	memmove(p, p + 1, n);
	p[n] = '\0';
	*s = (char*)p;
	p += n+1;
	return p;
}

static
uchar*
gqid(uchar *p, uchar *ep, Qid *q)
{
	if(p+QIDSZ > ep)
		return nil;
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
 * gqid() and gstring() return nil if they would reach beyond buffer.
 * main switch statement checks range and also can fall through
 * to test at end of routine.
 */
uint
convM2S(uchar *ap, uint nap, Fcall *f)
{
	uchar *p, *ep;
	uint i, size;

	p = ap;
	ep = p + nap;

fprint(2, "Checkpoint 1\n");
	if(p+BIT32SZ+BIT8SZ+BIT16SZ > ep)
		return 0;
	size = GBIT32(p);
	p += BIT32SZ;

fprint(2, "Checkpoint 2\n");
	if(size > nap)
		return 0;
	if(size < BIT32SZ+BIT8SZ+BIT16SZ)
		return 0;

fprint(2, "Checkpoint 3\n");
	f->type = GBIT8(p);
	p += BIT8SZ;
	f->tag = GBIT16(p);
	p += BIT16SZ;

fprint(2, "Checkpoint 4\n");
	switch(f->type)
	{
	default:
		return 0;

	case Tversion:
fprint(2, "Case Tversion\n");
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
fprint(2, "Case Tflush\n");
		if(p+BIT16SZ > ep)
			return 0;
		f->oldtag = GBIT16(p);
		p += BIT16SZ;
		break;

	case Tauth:
fprint(2, "Case Tauth\n");
		if(p+BIT32SZ > ep)
			return 0;
		f->afid = GBIT32(p);
		p += BIT32SZ;
		p = gstring(p, ep, &f->uname);
		if(p == nil)
			break;
		p = gstring(p, ep, &f->aname);
		if(p == nil)
			break;
		f->n_uname = GBIT32(p);
fprint(2, "     f->n_uname = %d\n", f->n_uname);
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
		if(p == nil)
			break;
		p = gstring(p, ep, &f->aname);
		if(p == nil)
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
fprint(2, "Case Tattach\n");
		if(p+BIT32SZ > ep)
			return 0;
		f->fid = GBIT32(p);
fprint(2, "     f->fid = %d\n", f->fid);
		p += BIT32SZ;
		if(p+BIT32SZ > ep)
			return 0;
		f->afid = GBIT32(p);
fprint(2, "     f->afid = %d\n", f->afid);
		p += BIT32SZ;
		p = gstring(p, ep, &f->uname);
		if(p == nil)
                {
fprint(2, "     FAILED getting f->unames\n");
			break;
                }
fprint(2, "     f->uname = %s\n", f->uname);
		p = gstring(p, ep, &f->aname);
		if(p == nil)
                {
fprint(2, "     FAILED getting f->aname\n");
			break;
                }
fprint(2, "     f->aname = %s\n", f->aname);
		if(p+BIT32SZ > ep)
                {
fprint(2, "     Went past end of buffer\n");
			return 0;
                }
		f->n_uname = GBIT32(p);
fprint(2, "     f->n_uname = %d\n", f->n_uname);
		p += BIT32SZ;
		break;


	case Twalk:
fprint(2, "Case Twalk\n");
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
		for(i=0; i<f->nwname; i++){
			p = gstring(p, ep, &f->wname[i]);
			if(p == nil)
				break;
		}
		break;

	case Topen:
fprint(2, "Case Topen\n");
		if(p+BIT32SZ+BIT8SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		f->mode = GBIT8(p);
		p += BIT8SZ;
		break;

	case Tcreate:
fprint(2, "Case Tcreate\n");
		if(p+BIT32SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		p = gstring(p, ep, &f->name);
		if(p == nil)
			break;
		if(p+BIT32SZ+BIT8SZ > ep)
			return 0;
		f->perm = GBIT32(p);
		p += BIT32SZ;
		f->mode = GBIT8(p);
		p += BIT8SZ;
		break;

	case Tread:
fprint(2, "Case Tread\n");
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
fprint(2, "Case Twrite\n");
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
fprint(2, "Case Tclunk\n");
	case Tremove:
fprint(2, "Case Tremove\n");
		if(p+BIT32SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		break;

	case Tstat:
fprint(2, "Case Tstat\n");
		if(p+BIT32SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		break;

	case Twstat:
fprint(2, "Case Twstat\n");
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
fprint(2, "Case Rversion\n");
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
		if(p == nil)
			break;
		p = gstring(p, ep, &f->authdom);
		break;
*/

	case Rerror:
fprint(2, "Case Rerror\n");
		p = gstring(p, ep, &f->ename);
fprint(2, "     f->ename = %s\n", f->ename);
		f->n_uname = GBIT32(p);
fprint(2, "     f->n_uname = %d\n", f->n_uname);
		p += BIT32SZ;
		break;

	case Rflush:
fprint(2, "Case Rflush\n");
		break;

/*
	case Rattach:
		p = gqid(p, ep, &f->qid);
		if(p == nil)
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
fprint(2, "Case Rattach\n");
		p = gqid(p, ep, &f->qid);
		if(p == nil)
			break;
		break;


	case Rwalk:
fprint(2, "Case Rwalk\n");
		if(p+BIT16SZ > ep)
			return 0;
		f->nwqid = GBIT16(p);
		p += BIT16SZ;
		if(f->nwqid > MAXWELEM)
			return 0;
		for(i=0; i<f->nwqid; i++){
			p = gqid(p, ep, &f->wqid[i]);
			if(p == nil)
				break;
		}
		break;

	case Ropen:
fprint(2, "Case Ropen\n");
	case Rcreate:
fprint(2, "Case Rcreate\n");
		p = gqid(p, ep, &f->qid);
		if(p == nil)
			break;
		if(p+BIT32SZ > ep)
			return 0;
		f->iounit = GBIT32(p);
		p += BIT32SZ;
		break;

	case Rread:
fprint(2, "Case Rread\n");
		if(p+BIT32SZ > ep)
			return 0;
		f->count = GBIT32(p);
fprint(2, "   f->count is %d\n", f->count);
		p += BIT32SZ;
		if(p+f->count > ep)
			return 0;
		f->data = (char*)p;
		p += f->count;
		break;

	case Rwrite:
fprint(2, "Case Rwrote\n");
		if(p+BIT32SZ > ep)
			return 0;
		f->count = GBIT32(p);
		p += BIT32SZ;
		break;

	case Rclunk:
fprint(2, "Case Rclunk\n");
	case Rremove:
fprint(2, "Case Rremove\n");
		break;

	case Rstat:
fprint(2, "Case Rstat\n");
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
fprint(2, "Case Rwstat\n");
		break;
	}

	if(p==nil || p>ep)
        {
if (p == nil)
fprint(2, "Returning 0 because p was NULL\n");
else
fprint(2, "Returning 0 because p > ep\n");
		return 0;
        }
	if(ap+size == p)
        {
fprint(2, "Returning size = %d\n", size);
		return size;
        }

fprint(2, "Default return 0\n");
	return 0;
}
