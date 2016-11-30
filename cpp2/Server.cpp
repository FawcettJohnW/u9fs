/* already in plan9.h #include <sys/types.h> *//* for struct passwd, struct group, struct stat ... */
/* plan9.h is first to get the large file support definitions as early as possible */
#include "Server.h"

using namespace Plan9;
using namespace Plan9::Common;
using namespace Plan9::Fcalls;
using namespace Plan9::FidMgr;
using namespace Plan9::P9UserMgmt;

void
Plan9::Server::P9Server::seterror(Fcall *f, char *error)
{
        static char programmererror[]="Programmer error";
Logging::fprint(2, "seterror entry\n");
	f->type = Rerror;
	f->ename = error ? error : programmererror;
}

int
Plan9::Server::P9Server::isowner(P9User *u, Fid *f)
{
Logging::fprint(2, "isowner entry\n");
	return u->id == f->st.st_uid;
}



void
Plan9::Server::P9Server::serve( void )
{

	Fcall rx, tx;
        static char badmessage[]="Bad message";
        int sock;

Logging::fprint(2, "serve entry\n");
	for(;;){
		m_Transport->getfcall(&sock, &rx);

Logging::fprint(2, "serve <- %F\n", &rx);
		if(chatty9p)
			Logging::fprint(2, "<- %F\n", &rx);

		memset(&tx, 0, sizeof tx);
		tx.type = rx.type+1;
		tx.tag = rx.tag;
		switch(rx.type){
		case Tflush:
Logging::fprint(2, "message type tflush\n");
			break;
		case Tversion:
Logging::fprint(2, "message type TVersion\n");
			rversion(&rx, &tx);
			break;
		case Tauth:
Logging::fprint(2, "message type Tauth\n");
			rauth(&rx, &tx);
			break;
		case Tattach:
Logging::fprint(2, "message type Tattach\n");
			rattach(&rx, &tx);
			break;
		case Twalk:
Logging::fprint(2, "message type Twalk\n");
			rwalk(&rx, &tx);
			break;
		case Tstat:
Logging::fprint(2, "message type Tstat\n");
			tx.stat = reinterpret_cast<p9uchar *>(m_Transport->databuf);
			rstat(&rx, &tx);
			break;
		case Twstat:
Logging::fprint(2, "message type Twstat\n");
			rwstat(&rx, &tx);
			break;
		case Topen:
Logging::fprint(2, "message type Topen\n");
			ropen(&rx, &tx);
			break;
		case Tcreate:
Logging::fprint(2, "message type Tcreate\n");
			rcreate(&rx, &tx);
			break;
		case Tread:
Logging::fprint(2, "message type Tread\n");
			tx.data = reinterpret_cast<char *>(m_Transport->databuf);
			rread(&rx, &tx);
			break;
		case Twrite:
Logging::fprint(2, "message type TWrite\n");
			rwrite(&rx, &tx);
			break;
		case Tclunk:
Logging::fprint(2, "message type Tclunk\n");
			rclunk(&rx, &tx);
			break;
		case Tremove:
Logging::fprint(2, "message type Tremove\n");
			rremove(&rx, &tx);
			break;
		default:
			Logging::fprint(2, "unknown message %F\n", &rx);
			seterror(&tx, badmessage);
			break;
		}

Logging::fprint(2, "serve -> %F\n", &tx);
		if(chatty9p)
			Logging::fprint(2, "-> %F\n", &tx);

		if (old9p)
                {
                    m_Transport->putfcallold(sock, &tx);
                }
                else
                {
                     m_Transport->putfcallnew(sock, &tx);
                }
	}
}

static char unknown[]="unknown";
static char ourversion[]="9P2000.u";

void
Plan9::Server::P9Server::rversion(Fcall *rx, Fcall *tx)
{
Logging::fprint(2, "rversion entry\n");
	if(msize > rx->msize)
		msize = rx->msize;
	tx->msize = msize;
	if(strncmp(rx->version, "9P", 2) != 0)
		tx->version = unknown;
	else
		tx->version = ourversion;
		// tx->version = "9P2000";
}

void
Plan9::Server::P9Server::rauth(Fcall *rx, Fcall *tx)
{
Logging::fprint(2, "rauth entry\n");
	char *e;

	// if((e = auth->MakeAuthCall(rx, tx)) != NULL)
		// seterror(tx, e);
}

static char nonestring[]="";
void
Plan9::Server::P9Server::rattach(Fcall *rx, Fcall *tx)
{
Logging::fprint(2, "rattach entry\n");
	char *e;
	Fid *fid;
	P9User *u;
        static char rootname[]="root";

	if(rx->aname == NULL)
		rx->aname = nonestring;

	if(strcmp(rx->aname, "device") == 0){
		if(connected && !devallowed){
			seterror(tx, Especial0);
			return;
		}
		devallowed = 1;
	}else{
		if(connected && devallowed){
			seterror(tx, Especial1);
			return;
		}
	}

	if(strcmp(rx->uname, "none") == 0){
		if(authed == 0){
			seterror(tx, Eauth);
			return;
		}
	} else {
		// if((e = auth->MakeAttachCall(rx, tx)) != NULL){
			// seterror(tx, e);
			// return;
		// }
		authed++;
	}

	if((fid = m_FidMgr->newfid(rx->fid, &e)) == NULL){
		seterror(tx, e);
		return;
	}
	fid->path = estrdup("/");
	if(m_FidMgr->fidstat(fid, &e) < 0){
		seterror(tx, e);
		m_FidMgr->freefid(fid);
		return;
	}

	if(defaultuser)
		rx->uname = defaultuser;

Logging::fprint(2, "Checking user name %s\n", rx->uname);
Logging::fprint(2, "      n_uname for user is %d\n", rx->n_uname);
	if((u = m_P9Users->uname2user(rx->uname)) == NULL
	|| (!defaultuser && u->id == 0)){
                rx->uname = rootname;
                // sprintf(rx->uname, "%d", rx->n_uname);
Logging::fprint(2, "Horked the user name to %s\n", rx->uname);
	}
Logging::fprint(2, "Clear\n");

	fid->u = u;
	tx->qid = m_FileSystemUserOps->stat2qid(&fid->st);
	return;
}

void
Plan9::Server::P9Server::rwalk(Fcall *rx, Fcall *tx)
{
Logging::fprint(2, "rwalk entry\n");
	int i;
	char *path, *e;
	Fid *fid, *nfid;

	e = NULL;
	if((fid = m_FidMgr->oldfid(rx->fid, &e)) == NULL){
		seterror(tx, e);
		return;
	}

	if(fid->omode != -1){
		seterror(tx, Ebadusefid);
		return;
	}

	if(m_FidMgr->fidstat(fid, &e) < 0){
		seterror(tx, e);
		return;
	}

	if(!S_ISDIR(fid->st.st_mode) && rx->nwname){
		seterror(tx, Enotdir);
		return;
	}

	nfid = NULL;
	if(rx->newfid != rx->fid && (nfid = m_FidMgr->newfid(rx->newfid, &e)) == NULL){
		seterror(tx, e);
		return;
	}

	path = estrdup(fid->path);
	e = NULL;
	for(i=0; i<rx->nwname; i++)
		if(m_FileSystemUserOps->userwalk(fid->u, &path, rx->wname[i], &tx->wqid[i], &e) < 0)
			break;

	if(i == rx->nwname){		/* successful clone or walk */
		tx->nwqid = i;
		if(nfid){
			nfid->path = path;
			nfid->u = fid->u;
		}else{
			free(fid->path);
			fid->path = path;
		}
	}else{
		if(i > 0)		/* partial walk? */
			tx->nwqid = i;
		else
			seterror(tx, e);

		if(nfid)		/* clone implicit new fid */
			m_FidMgr->freefid(nfid);
		free(path);
	}
	return;
}

void
Plan9::Server::P9Server::ropen(Fcall *rx, Fcall *tx)
{
Logging::fprint(2, "ropen entry\n");
	char *e;
	Fid *fid;

	if((fid = m_FidMgr->oldfid(rx->fid, &e)) == NULL){
		seterror(tx, e);
		return;
	}

	if(fid->omode != -1){
		seterror(tx, Ebadusefid);
		return;
	}

	if(m_FidMgr->fidstat(fid, &e) < 0){
		seterror(tx, e);
		return;
	}

	if(!devallowed && S_ISSPECIAL(fid->st.st_mode)){
		seterror(tx, Especial);
		return;
	}

	if(m_FileSystemUserOps->useropen(fid, rx->mode, &e) < 0){
		seterror(tx, e);
		return;
	}

	tx->iounit = 0;
	tx->qid = m_FileSystemUserOps->stat2qid(&fid->st);
}

void
Plan9::Server::P9Server::rcreate(Fcall *rx, Fcall *tx)
{
Logging::fprint(2, "rcreate entry\n");
	char *e;
	Fid *fid;

Logging::fprint(2, "Checking oldfid...\n");
	if((fid = m_FidMgr->oldfid(rx->fid, &e)) == NULL){
		seterror(tx, e);
		return;
	}

Logging::fprint(2, "Checking mode...\n");
	if(fid->omode != -1){
		seterror(tx, Ebadusefid);
		return;
	}

Logging::fprint(2, "Checking m_FidMgr->fidstat...\n");
	if(m_FidMgr->fidstat(fid, &e) < 0){
		seterror(tx, e);
		return;
	}

Logging::fprint(2, "Checking ISDIR...\n");
	if(!S_ISDIR(fid->st.st_mode)){
		seterror(tx, Enotdir);
		return;
	}

Logging::fprint(2, "rcreate attempting to create file %s\n", rx->name);
	if(m_FileSystemUserOps->usercreate(fid, rx->name, rx->n_uname, 65534, rx->mode, rx->perm, &e) < 0){
Logging::fprint(2, "create failed %s\n", rx->name);
		seterror(tx, e);
		return;
	}

Logging::fprint(2, "rcreate attempting to stat file %s\n", rx->name);
	if(m_FidMgr->fidstat(fid, &e) < 0){
Logging::fprint(2, "stat failed %s\n", rx->name);
		seterror(tx, e);
		return;
	}

	tx->iounit = 0;
	tx->qid = m_FileSystemUserOps->stat2qid(&fid->st);
}

/* 
 * this is for chmod, so don't worry about S_IFDIR
 */
mode_t
Plan9::Server::P9Server::unixmode(Dir *d)
{
Logging::fprint(2, "unixmode entry\n");
	return (mode_t)(d->mode&0777);
}

void
Plan9::Server::P9Server::rread(Fcall *rx, Fcall *tx)
{
Logging::fprint(2, "rread entry\n");
	char *e, *path, *rpath;
	uchar *p, *ep;
	int n;
	Fid *fid;
	Dir d;
	struct stat st;

	if(rx->count > msize-IOHDRSZ){
		seterror(tx, Etoolarge);
		return;
	}

	if((fid = m_FidMgr->oldfidex(rx->fid, -1, &e)) == NULL){
		seterror(tx, e);
		return;
	}

	if (fid->auth) {
		char *e;
		// e = auth->MakeReadCall(rx, tx);
		// if (e)
			// seterror(tx, e);
		return;
	}

	if(fid->omode == -1 || (fid->omode&3) == OWRITE){
		seterror(tx, Ebadusefid);
		return;
	}

	if(fid->dir){
		if(rx->offset != fid->diroffset){
			if(rx->offset != 0){
				seterror(tx, Ebadoffset);
				return;
			}
			rewinddir(fid->dir);
			fid->diroffset = 0;
			fid->direof = 0;
		}
		if(fid->direof){
			tx->count = 0;
			return;
		}

		p = (uchar*)tx->data;
		ep = (uchar*)tx->data+rx->count;
		for(;;){
			if(p+BIT16SZ >= ep)
				break;
			if(fid->dirent == NULL)	/* one entry cache for when convD2M fails */
				if((fid->dirent = readdir(fid->dir)) == NULL){
					fid->direof = 1;
					break;
				}
			if(strcmp(fid->dirent->d_name, ".") == 0
			|| strcmp(fid->dirent->d_name, "..") == 0){
				fid->dirent = NULL;
				continue;
			}
			rpath = m_FileSystemUserOps->rootpath(fid->path);
			path = estrpath(rpath, fid->dirent->d_name, 0);
			memset(&st, 0, sizeof st);
			if(m_FileSystemUserOps->doStat(path, &st) < 0){
				Logging::fprint(2, "dirread: stat(%s) failed: %s\n", path, strerror(errno));
				fid->dirent = NULL;
				free(path);
				continue;
			}
			free(path);
			m_FileSystemUserOps->stat2dir(fid->dirent->d_name, &st, &d);
			if((n=(old9p ? convD2Mold : convD2M)(&d, p, ep-p)) <= BIT16SZ)
				break;
			p += n;
			fid->dirent = NULL;
		}
		tx->count = p - (uchar*)tx->data;
		fid->diroffset += tx->count;
	}else{
		if((n = pread(fid->fd, tx->data, rx->count, rx->offset)) < 0){
Logging::fprint(2, "strerror general 1\n");
			seterror(tx, strerror(errno));
			return;
		}
		tx->count = n;
	}
}

void
Plan9::Server::P9Server::rwrite(Fcall *rx, Fcall *tx)
{
Logging::fprint(2, "rwrite entry\n");
	char *e;
	Fid *fid;
	int n;

	if(rx->count > msize-IOHDRSZ){
		seterror(tx, Etoolarge);
		return;
	}

	if((fid = m_FidMgr->oldfidex(rx->fid, -1, &e)) == NULL){
		seterror(tx, e);
		return;
	}

	if (fid->auth) {
		char *e;
		// e = auth->MakeWriteCall(rx, tx);
		// if (e)
			// seterror(tx, e);
		return;
	}

	if(fid->omode == -1 || (fid->omode&3) == OREAD || (fid->omode&3) == OEXEC){
		seterror(tx, Ebadusefid);
		return;
	}

	if((n = pwrite(fid->fd, rx->data, rx->count, rx->offset)) < 0){
Logging::fprint(2, "strerror general 2\n");
		seterror(tx, strerror(errno));
		return;
	}
	tx->count = n;
}

void
Plan9::Server::P9Server::rclunk(Fcall *rx, Fcall *tx)
{
Logging::fprint(2, "rclunk entry\n");
	char *e, *rpath;
	Fid *fid;

	if((fid = m_FidMgr->oldfidex(rx->fid, -1, &e)) == NULL){
		seterror(tx, e);
		return;
	}
	if (fid->auth) {
		// e = (auth->MakeClunkCall)(rx, tx);
		// if (e && strcmp(e, errStr) != 0) {
			// seterror(tx, e);
			// return;
		// }
	}
	else if(fid->omode != -1 && fid->omode&ORCLOSE){
		rpath = m_FileSystemUserOps->rootpath(fid->path);
		remove(rpath);
	}
	m_FidMgr->freefid(fid);
}

void
Plan9::Server::P9Server::rremove(Fcall *rx, Fcall *tx)
{
Logging::fprint(2, "rremove entry\n");
	char *e;
	Fid *fid;

	if((fid = m_FidMgr->oldfid(rx->fid, &e)) == NULL){
		seterror(tx, e);
		return;
	}
	if(m_FileSystemUserOps->userremove(fid, &e) < 0)
		seterror(tx, e);
	m_FidMgr->freefid(fid);
}

void
Plan9::Server::P9Server::rstat(Fcall *rx, Fcall *tx)
{
	char *e;
	Fid *fid;
	Dir d;
        static char convfailed[]="convD2M fails";

	if((fid = m_FidMgr->oldfid(rx->fid, &e)) == NULL){
		seterror(tx, e);
		return;
	}

Logging::fprint(2, "rstat entry for fid->path = %s\n", fid->path);
	if(m_FidMgr->fidstat(fid, &e) < 0){
		seterror(tx, e);
		return;
	}

	m_FileSystemUserOps->stat2dir(fid->path, &fid->st, &d);
	if((tx->nstat=(old9p ? convD2Mold : convD2M)(&d, tx->stat, msize)) <= BIT16SZ)
		seterror(tx, convfailed);
Logging::fprint(2, "rstat exit\n");
}

void
Plan9::Server::P9Server::rwstat(Fcall *rx, Fcall *tx)
{
	char *e, *opath, *npath;
	char *p, *oldname, *newname, *dir;
	gid_t gid;
	Dir d;
	Fid *fid;
	static char nostat[]="no wstat of root";
	static char totallybogus[]="whoops: can't happen in u9fs";

Logging::fprint(2, "rwstat entry\n");
	if((fid = m_FidMgr->oldfid(rx->fid, &e)) == NULL){
		seterror(tx, e);
		return;
	}

	/*
	 * wstat is supposed to be atomic.
	 * we check all the things we can before trying anything.
	 * still, if we are told to truncate a file and rename it and only
	 * one works, we're screwed.  in such cases we leave things
	 * half broken and return an error.  it's hardly perfect.
	 */
	if((old9p ? convM2Dold : convM2D)(rx->stat, rx->nstat, &d, (char*)rx->stat) <= BIT16SZ){
		seterror(tx, Ewstatbuffer);
		return;
	}

	if(m_FidMgr->fidstat(fid, &e) < 0){
		seterror(tx, e);
		return;
	}

	/*
	 * The casting is necessary because d.mode is ulong and might,
	 * on some systems, be 64 bits.  We only want to compare the
	 * bottom 32 bits, since that's all that gets sent in the protocol.
	 * 
	 * Same situation for d.mtime and d.length (although that last check
	 * is admittedly superfluous, given the current lack of 128-bit machines).
	 */
	gid = (gid_t)-1;
	if(d.gid[0] != '\0'){
		P9User *g;

		g = m_P9Users->gname2user(d.gid);
		if(g == NULL){
			seterror(tx, Eunknowngroup);
			return;
		}
		gid = (gid_t)g->id;

		if(m_FileSystemUserOps->groupchange(fid->u, m_P9Users->gid2user(gid), &e) < 0){
			seterror(tx, e);
			return;
		}		
	}

	if((u32int)d.mode != (u32int)~0 && (((d.mode&DMDIR)!=0) ^ (S_ISDIR(fid->st.st_mode)!=0))){
		seterror(tx, Edirchange);
		return;
	}

	if(strcmp(fid->path, "/") == 0){
		seterror(tx, nostat);
		return;
	}

	/*
	 * try things in increasing order of harm to the file.
	 * mtime should come after truncate so that if you
	 * do both the mtime actually takes effect, but i'd rather
	 * leave truncate until last.
	 * (see above comment about atomicity).
	 */
	opath = estrdup(m_FileSystemUserOps->rootpath(fid->path));
	if((u32int)d.mode != (u32int)~0 && chmod(opath, unixmode(&d)) < 0){
		if(chatty9p)
			Logging::fprint(2, "chmod(%s, 0%luo) failed\n", opath, unixmode(&d));
Logging::fprint(2, "strerror general 3\n");
		seterror(tx, strerror(errno));
		return;
	}

	if((u32int)d.mtime != (u32int)~0){
		struct utimbuf t;

		t.actime = 0;
		t.modtime = d.mtime;
		if(utime(opath, &t) < 0){
			if(chatty9p)
				Logging::fprint(2, "utime(%s) failed\n", opath);
Logging::fprint(2, "strerror general 4\n");
			seterror(tx, strerror(errno));
			return;
		}
	}

	if(gid != (gid_t)-1 && gid != fid->st.st_gid){
		if(chown(opath, (uid_t)-1, gid) < 0){
			if(chatty9p)
				Logging::fprint(2, "chgrp(%s, %d) failed\n", opath, gid);
Logging::fprint(2, "strerror general 5\n");
			seterror(tx, strerror(errno));
			return;
		}
	}

	if(d.name[0]){
		oldname = fid->path;
		dir = estrdup(fid->path);
		if((p = strrchr(dir, '/')) > dir)
			*p = '\0';
		else{
			seterror(tx, totallybogus);
			return;
		}
		newname = estrpath(dir, d.name, 1);
		npath = m_FileSystemUserOps->rootpath(newname);
		if(strcmp(oldname, newname) != 0 && rename(opath, npath) < 0){
			if(chatty9p)
				Logging::fprint(2, "rename(%s, %s) failed\n", oldname, newname);
Logging::fprint(2, "strerror general 6\n");
			seterror(tx, strerror(errno));
			free(newname);
			free(dir);
			free(opath);
			return;
		}
		fid->path = newname;
		free(oldname);
		free(dir);
		free(opath);
	}

	if((u64int)d.length != (u64int)~0 && truncate(opath, d.length) < 0){
		Logging::fprint(2, "truncate(%s, %lld) failed\n", opath, d.length);
Logging::fprint(2, "strerror general 7\n");
		seterror(tx, strerror(errno));
		return;
	}
}
