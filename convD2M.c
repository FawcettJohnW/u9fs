#include	<plan9.h>
#include	<fcall.h>

uint
sizeD2M(Dir *d)
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
convD2M(Dir *d, uchar *buf, uint nbuf)
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
