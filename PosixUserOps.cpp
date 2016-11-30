#include "PosixUserOps.h"

#include <stdio.h>

static char	Enotingroup[]     = "not a member of proposed group";
static char     Eperm[]           = "permission denied";
static char     Eexist[]          = "file or directory already exists";
static char     ProgrammerError[] = "programmer error";
static char     EmptyString[]     = "";

static char isfrog[256]={
                /*NUL*/ 1, 1, 1, 1, 1, 1, 1, 1,
                /*BKS*/ 1, 1, 1, 1, 1, 1, 1, 1,
                /*DLE*/ 1, 1, 1, 1, 1, 1, 1, 1,
                /*CAN*/ 1, 1, 1, 1, 1, 1, 1, 1,
                /*' '*/ 0, 0, 0, 0, 0, 0, 0, 0,
                /*'('*/ 0, 0, 0, 0, 0, 0, 0, 1, /*'/'*/
                /*'0'*/ 0, 0, 0, 0, 0, 0, 0, 0,
                /*'8'*/ 0, 0, 0, 0, 0, 0, 0, 0,
                /*'@'*/ 0, 0, 0, 0, 0, 0, 0, 0,
                /*'H'*/ 0, 0, 0, 0, 0, 0, 0, 0,
                /*'P'*/ 0, 0, 0, 0, 0, 0, 0, 0,
                /*'X'*/ 0, 0, 0, 0, 0, 0, 0, 0,
                /*'`'*/ 0, 0, 0, 0, 0, 0, 0, 0,
                /*'h'*/ 0, 0, 0, 0, 0, 0, 0, 0,
                /*'p'*/ 0, 0, 0, 0, 0, 0, 0, 0,
                /*'x'*/ 0, 0, 0, 0, 0, 0, 0, 1, /*DEL*/
        };

Plan9::FileSystem::PosixUserOps::~PosixUserOps( void )
{
}

int
Plan9::FileSystem::PosixUserOps::fidstat(Fid *fid, char **ep)
{
	char *rpath;

	rpath = rootpath(fid->path);
	if(lstat(rpath, &fid->st) < 0){
		Logging::fprint(2, "fidstat(%s) failed\n", rpath);
		if(ep)
			*ep = strerror(errno);
		return -1;
	}
	if(S_ISDIR(fid->st.st_mode))
		fid->st.st_size = 0;
	return 0;
}

int
Plan9::FileSystem::PosixUserOps::userchange(P9User *u, char **ep)
{
        static char errstr[] = "cannot setuid back to root";

	if(defaultuser)
		return 0;

	if(setreuid(0, 0) < 0){
		Logging::fprint(2, "setreuid(0, 0) failed\n");
		*ep = errstr;
		return -1;
	}

	/*
	 * Initgroups does not appear to be SUSV standard.
	 * But it exists on SGI and on Linux, which makes me
	 * think it's standard enough.  We have to do something
	 * like this, and the closest other function I can find is
	 * setgroups (which initgroups eventually calls).
	 * Setgroups is the same as far as standardization though,
	 * so we're stuck using a non-SUSV call.  Sigh.
	 */
	if(initgroups(u->name, u->defaultgid) < 0)
		Logging::fprint(2, "initgroups(%s) failed: %s\n", u->name, strerror(errno));

	if(setreuid(-1, u->id) < 0){
		Logging::fprint(2, "setreuid(-1, %s) failed\n", u->name);
		*ep = strerror(errno);
		return -1;
	}

	return 0;
}

/*
 * We do our own checking here, then switch to root temporarily
 * to set our gid.  In a perfect world, you'd be allowed to set your
 * egid to any of the supplemental groups of your euid, but this
 * is not the case on Linux 2.2.14 (and perhaps others).
 *
 * This is a race, of course, but it's a race against processes
 * that can edit the group lists.  If you can do that, you can
 * change your own group without our help.
 */
int
Plan9::FileSystem::PosixUserOps::groupchange(P9User *u, P9User *g, char **ep)
{
	if(g == NULL)
		return -1;
	if(!m_P9Users->useringroup(u, g)){
		if(chatty9p)
			Logging::fprint(2, "%s not in group %s\n", u->name, g->name);
		*ep = Enotingroup;
		return -1;
	}

	setreuid(0,0);
	if(setregid(-1, g->id) < 0){
		Logging::fprint(2, "setegid(%s/%d) failed in groupchange\n", g->name, g->id);
		*ep = strerror(errno);
		return -1;
	}
	if(userchange(u, ep) < 0)
		return -1;

	return 0;
}


/*
 * An attempt to enforce permissions by looking at the 
 * file system.  Separation of checking permission and
 * actually performing the action is a terrible idea, of 
 * course, so we use setreuid for most of the permission
 * enforcement.  This is here only so we can give errors
 * on open(ORCLOSE) in some cases.
 */
int
Plan9::FileSystem::PosixUserOps::userperm(P9User *u, char *path, int type, int need)
{
	char *p, *q, *rpath;
	int i, have;
	struct stat st;
	P9User *g;

	switch(type){
	default:
		Logging::fprint(2, "bad type %d in userperm\n", type);
		return -1;
	case Tdot:
		rpath = rootpath(path);
		if(lstat(rpath, &st) < 0){
			Logging::fprint(2, "userperm: stat(%s) failed\n", rpath);
			return -1;
		}
		break;
	case Tdotdot:
		rpath = rootpath(path);
		p = estrdup(rpath);
		if((q = strrchr(p, '/'))==NULL){
			Logging::fprint(2, "userperm(%s, ..): bad path\n", p);
			free(p);
			return -1;
		}
		if(q > p)
			*q = '\0';
		else
			*(q+1) = '\0';
		if(lstat(p, &st) < 0){
			Logging::fprint(2, "userperm: stat(%s) (dotdot of %s) failed\n",
				p, rpath);
			free(p);
			return -1;
		}
		free(p);
		break;
	}

	if(u == none){
		Logging::fprint(2, "userperm: none wants %d in 0%luo\n", need, st.st_mode);
		have = st.st_mode&7;
		if((have&need)==need)
			return 0;
		return -1;
	}
	have = st.st_mode&7;
	if((uid_t)u->id == st.st_uid)
		have |= (st.st_mode>>6)&7;
	if((have&need)==need)
		return 0;
	if(((have|((st.st_mode>>3)&7))&need) != need)	/* group won't help */
		return -1;
	g = m_P9Users->gid2user(st.st_gid);
	for(i=0; i<g->nmem; i++){
		if(strcmp(g->mem[i], u->name) == 0){
			have |= (st.st_mode>>3)&7;
			break;
		}
	}
	if((have&need)==need)
		return 0;
	return -1;
}

int
Plan9::FileSystem::PosixUserOps::userwalk(P9User *u, char **path, char *elem, Qid *qid, char **ep)
{
	char *npath, *rpath;
	struct stat st;

	npath = estrpath(*path, elem, 1);
	rpath = rootpath(npath);
	if(lstat(rpath, &st) < 0){
		free(npath);
		*ep = strerror(errno);
		return -1;
	}
	*qid = stat2qid(&st);
	free(*path);
	*path = npath;
	return 0;
}

int
Plan9::FileSystem::PosixUserOps::useropen(Fid *fid, int omode, char **ep)
{
	int a, o;
	char *rpath;

	/*
	 * Check this anyway, to try to head off problems later.
	 */
	if((omode&ORCLOSE) && userperm(fid->u, fid->path, Tdotdot, W_OK) < 0){
		*ep = Eperm;
		return -1;
	}
	switch(omode&3){
	default:
		*ep = ProgrammerError;
		return -1;
	case OREAD:
		a = R_OK;
		o = O_RDONLY;
		break;
	case ORDWR:
		a = R_OK|W_OK;
		o = O_RDWR;
		break;
	case OWRITE:
		a = W_OK;
		o = O_WRONLY;
		break;
	case OEXEC:
		a = X_OK;
		o = O_RDONLY;
		break;
	}
	if(omode & OTRUNC){
		a |= W_OK;
		o |= O_TRUNC;
	}

	if(S_ISDIR(fid->st.st_mode)){
		if(a != R_OK){
			Logging::fprint(2, "attempt by %s to open dir %d\n", fid->u->name, omode);
			*ep = Eperm;
			return -1;
		}
		rpath = rootpath(fid->path);
		if((fid->dir = opendir(rpath)) == NULL){
			*ep = strerror(errno);
			return -1;
		}
	}else{
		/*
		 * This is wrong because access used the real uid
		 * and not the effective uid.  Let the open sort it out.
		 *
		if(access(fid->path, a) < 0){
			*ep = strerror(errno);
			return -1;
		}
		 *
		 */
		rpath = rootpath(fid->path);
		if((fid->fd = open(rpath, o)) < 0){
			*ep = strerror(errno);
			return -1;
		}
	}
	fid->omode = omode;
	return 0;
}

int
Plan9::FileSystem::PosixUserOps::usercreate(Fid *fid, char *elem, int uid, int gid, int omode, long perm, char **ep)
{
Logging::fprint(2, "usercreate entry\n");
	int o, m;
	char *opath, *npath, *rpath;
	struct stat st, parent;
	P9User *u;

	rpath = rootpath(fid->path);
	if(lstat(rpath, &parent) < 0){
Logging::fprint(2, "strerror general 12\n");
		*ep = strerror(errno);
		return -1;
	}

#ifdef NO
	/*
	 * Change group so that created file has expected group
	 * by Plan 9 semantics.  If that fails, might as well go
	 * with the user's default group.
	 */
	if(groupchange(fid->u, m_P9Users->gid2user(parent.st_gid), ep) < 0
	&& groupchange(fid->u, m_P9Users->gid2user(fid->u->defaultgid), ep) < 0)
		return -1;
#endif

	m = (perm & DMDIR) ? 0777 : 0666;
	perm = perm & (~m | (fid->st.st_mode & m));

	npath = estrpath(rpath, elem, 1);
	if(perm & DMDIR){
		if((omode&~ORCLOSE) != OREAD){
Logging::fprint(2, "Setting permission denied failure from usercreate\n");
			*ep = Eperm;
			free(npath);
			return -1;
		}
		if(lstat(npath, &st) >= 0 || errno != ENOENT){
			*ep = Eexist;
			free(npath);
			return -1;
		}
		/* race */
		if(mkdir(npath, perm&0777) < 0){
Logging::fprint(2, "Setting permission denied failure from usercreate mkdir\n");
			*ep = strerror(errno);
			free(npath);
			return -1;
		}
		if((fid->dir = opendir(npath)) == NULL){
Logging::fprint(2, "Setting permission denied failure from usercreate mkdir 2\n");
			*ep = strerror(errno);
			remove(npath);		/* race */
			free(npath);
			return -1;
		}
	}else{
		o = O_CREAT|O_EXCL;
		switch(omode&3){
		default:
		        *ep = ProgrammerError;
			return -1;
		case OREAD:
		case OEXEC:
			o |= O_RDONLY;
			break;
		case ORDWR:
			o |= O_RDWR;
			break;
		case OWRITE:
			o |= O_WRONLY;
			break;
		}
		if(omode & OTRUNC)
			o |= O_TRUNC;
		if((fid->fd = open(npath, o, perm&0777)) < 0){
			if(chatty9p)
				Logging::fprint(2, "create(%s, 0x%x, 0%o) failed\n", npath, o, perm&0777);
			*ep = strerror(errno);
			free(npath);
			return -1;
		}
	}

	/*
	 * Change ownership if a default user is specified.
	 */
Logging::fprint(2, "chown changing file %s to owner %d\n", npath, uid);
        if (chown(npath, uid, -1) < 0)
        {
            Logging::fprint(2, "chown after create on %s failed\n", npath);
            return -1;
        }

#ifdef NO
	if(defaultuser)
	if((u = uname2user(defaultuser)) == NULL
	|| chown(npath, u->id, -1) < 0){
		fprint(2, "chown after create on %s failed\n", npath);
		remove(npath);	/* race */
		free(npath);
		fid->path = opath;
		if(fid->fd >= 0){
			close(fid->fd);
			fid->fd = -1;
		}else{
			closedir(fid->dir);
			fid->dir = NULL;
		}
		return -1;
	}
#endif

	opath = fid->path;
	fid->path = estrpath(opath, elem, 1);
	if(fidstat(fid, ep) < 0){
		Logging::fprint(2, "stat after create on %s failed\n", npath);
		remove(npath);	/* race */
		free(npath);
		fid->path = opath;
		if(fid->fd >= 0){
			close(fid->fd);
			fid->fd = -1;
		}else{
			closedir(fid->dir);
			fid->dir = NULL;
		}
		return -1;
	}
	fid->omode = omode;
	free(opath);
	return 0;
}

int
Plan9::FileSystem::PosixUserOps::userremove(Fid *fid, char **ep)
{
	char *rpath;

	rpath = rootpath(fid->path);
	if(remove(rpath) < 0){
		*ep = strerror(errno);
		return -1;
	}
	return 0;
}

char*
Plan9::FileSystem::PosixUserOps::rootpath(char *path)
{
        static char buf[PATH_MAX];

        if(root == NULL)
                return path;
        Logging::snprint(buf, sizeof buf, "%s%s", root, path);
	return buf;
}

Qid
Plan9::FileSystem::PosixUserOps::stat2qid(struct stat *st)
{
        uchar *p, *ep, *q;
        Qid qid;
Logging::fprint(2, "stat2qid entry\n");

        /*
         * For now, ignore the device number.
         */
        qid.path = 0;
        p = (uchar*)&qid.path;
        ep = p+sizeof(qid.path);
        q = p+sizeof(ino_t);
        if(q > ep){
                Logging::fprint(2, "warning: inode number too big\n");
                q = ep;
        }
        memmove(p, &st->st_ino, q-p);
        q = q+sizeof(dev_t);
        if(q > ep){
/*
 *              Logging::fprint(2, "warning: inode number + device number too big %d+%d\n",
 *                      sizeof(ino_t), sizeof(dev_t));
 */
                q = ep - sizeof(dev_t);
                if(q < p)
                        Logging::fprint(2, "warning: device number too big by itself\n");
                else
                        *(dev_t*)q ^= st->st_dev;
        }

        qid.vers = st->st_mtime ^ (st->st_size << 8);
        qid.type = modebyte(st);
Logging::fprint(2, "stat2qid set type to %d\n", qid.type);
        return qid;
}

void
Plan9::FileSystem::PosixUserOps::stat2dir(char *path, struct stat *st, Dir *d)
{
        P9User *u;
        char *q, *p, *npath;
Logging::fprint(2, "stat2dir entry for path %s\n", path);

        memset(d, 0, sizeof(*d));
        d->qid = stat2qid(st);
        d->mode = plan9mode(st);
        d->atime = st->st_atime;
        d->mtime = st->st_mtime;
        d->length = st->st_size;

        // d->uid = (u = m_P9Users->uid2user(st->st_uid)) ? u->name : "???";
        // d->gid = (u = m_P9Users->gid2user(st->st_gid)) ? u->name : "???";
        // d->muid = "";
        d->uid = EmptyString;
        d->gid = EmptyString;
        d->muid = EmptyString;

        d->extension = EmptyString;
        int linkChunkSize = 1024;
        if (S_ISLNK(st->st_mode))
        {
            int linkRead = 0;

            ssize_t pathLength;
            char* linkName;

            while (0 == linkRead)
            {
                linkName = reinterpret_cast<char *>(emalloc(linkChunkSize));

                if (linkName)
                {
                    if ((pathLength = readlink(path, linkName, linkChunkSize) < 0))
                    {
                        if (errno == ENAMETOOLONG)
                        {
                            linkChunkSize *= 2;
                            continue;
                        }
                        else
                        {
                            break;
                        }
                    }
                    else
                    {
                        Logging::fprint(2, "Link points to %s\n", linkName);
                        d->extension = linkName;
                        linkRead = 1;
                        break;
                    }
                }
                else
                {
                    break;
                }
            }
Logging::fprint(2, "File is symbolic link\n");
        }

        d->n_uid = st->st_uid;
        d->n_gid = st->st_gid;
        d->n_muid = 0;

        if((q = strrchr(path, '/')) != NULL)
        {
Logging::fprint(2, "stat2dir enfrogging  short path %s\n", q);
                d->name = enfrog(q+1);
        }
        else
        {
Logging::fprint(2, "stat2dir enfrogging  path %s\n", path);
                d->name = enfrog(path);
        }
Logging::fprint(2, "stat2dir complete\n");
}

uchar
Plan9::FileSystem::PosixUserOps::modebyte(struct stat *st)
{
	uchar b;
Logging::fprint(2, "modebyte entry\n");

	b = 0;

	if(S_ISDIR(st->st_mode))
        {
		b |= QTDIR;
Logging::fprint(2, "modebyte set DIR bit\n");

        }

        if (S_ISLNK(st->st_mode))
        {
		b |= QTSYMLINK;
Logging::fprint(2, "modebyte set SYMLINK bit\n");
        }

        if (st->st_nlink > 0)
        {
		b |= QTLINK;
Logging::fprint(2, "modebyte set HARDLINK bit\n");
        }

	/* no way to test append-only */
	/* no real way to test exclusive use, but mark devices as such */
	if(S_ISSPECIAL(st->st_mode))
        {
		b |= QTEXCL;
        }

	return b;
}

ulong
Plan9::FileSystem::PosixUserOps::plan9mode(struct stat *st)
{
Logging::fprint(2, "plan9mode entry\n");
        return ((ulong)modebyte(st)<<24) | (st->st_mode & 0777);
}

char *
Plan9::FileSystem::PosixUserOps::enfrog(char *src)
{
        char *d, *dst;
        uchar *s;
Logging::fprint(2, "enfrog entry\n");

        d = dst = reinterpret_cast<char *>(emalloc(strlen(src)*3 + 1));
        for (s = (uchar *)src; *s; s++)
                if(isfrog[*s] || *s == '\\')
                        d += sprintf(d, "\\%02x", *s);
                else
                        *d++ = *s;
        *d = 0;
        return dst;
}

char *
Plan9::FileSystem::PosixUserOps::defrog(char *s)
{
        char *d, *dst, buf[3];
Logging::fprint(2, "defrog entry\n");

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

int
Plan9::FileSystem::PosixUserOps::doStat(const char *path, struct stat *buf)
{
    return lstat(path, buf);
}
