#include "P9Common.h"
#include "Fid.h"
#include "IFileSystemUserOps.h"

using namespace Plan9;
using namespace Plan9::Common;
using namespace Plan9::P9UserMgmt;

FidMgr::Fid*
FidMgr::FidMgr::lookupfid(int fid)
{
	Fid *f;

	for(f=fidtab[fid%nelem(fidtab)]; f; f=f->next)
		if(f->fid == fid)
			return f;
	return NULL;
}

FidMgr::Fid*
FidMgr::FidMgr::newfid(int fid, char **ep)
{
	Fid *f(new Fid());

	if(lookupfid(fid) != NULL){
		*ep = Efidactive;
		return NULL;
	}

	f->next = fidtab[fid%nelem(fidtab)];
	if(f->next)
		f->next->prev = f;
	fidtab[fid%nelem(fidtab)] = f;
	f->fid = fid;
	f->fd = -1;
	f->omode = -1;
	return f;
}

FidMgr::Fid*
FidMgr::FidMgr::newauthfid(int fid, void *magic, char **ep)
{
	Fid *af;
	af = newfid(fid, ep);
	if (af == NULL)
		return NULL;
	af->auth = 1;
	af->authmagic = magic;
	return af;
}

FidMgr::Fid*
FidMgr::FidMgr::oldfidex(int fid, int auth, char **ep)
{
	Fid *f;

	if((f = lookupfid(fid)) == NULL){
		*ep = Ebadfid;
		return NULL;
	}

	if (auth != -1 && f->auth != auth) {
		*ep = Ebadfid;
		return NULL;
	}

#ifdef JWF_NEED_TO_FIGURE_OUT_HOW_TO_BRANCH_HERE
	if (!f->auth) {
		if(Plan9::Common::m_UsrMgr->userchange(f->u, ep) < 0)
			return NULL;
	}
#endif

	return f;
}

FidMgr::Fid*
FidMgr::FidMgr::oldfid(int fid, char **ep)
{
	return oldfidex(fid, 0, ep);
}

FidMgr::Fid*
FidMgr::FidMgr::oldauthfid(int fid, void **magic, char **ep)
{
	Fid *af;
	af = oldfidex(fid, 1, ep);
	if (af == NULL)
		return NULL;
	*magic = af->authmagic;
	return af;
}

void
FidMgr::FidMgr::freefid(Fid *f)
{
	if(f->prev)
		f->prev->next = f->next;
	else
		fidtab[f->fid%nelem(fidtab)] = f->next;
	if(f->next)
		f->next->prev = f->prev;
	if(f->dir)
		closedir(f->dir);
	if(f->fd)
		close(f->fd);
	free(f->path);
	delete(f);
}

int
FidMgr::FidMgr::fidstat(Fid *fid, char **ep)
{
	char *rpath;

	rpath = m_UsrOps->rootpath(fid->path);
	if(m_UsrOps->doStat(rpath, &fid->st) < 0){
		Logging::fprint(2, "fidstat(%s) failed\n", rpath);
		if(ep)
			*ep = strerror(errno);
		return -1;
	}
	if(S_ISDIR(fid->st.st_mode))
		fid->st.st_size = 0;
	return 0;
}
