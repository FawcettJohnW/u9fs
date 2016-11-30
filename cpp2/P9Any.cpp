/*
 * 4th Edition p9any/p9sk1 authentication based on auth9p1.c
 * Nigel Roles (nigel@9fs.org) 2003
 */

#include "P9Any.h"
#include "Logging.h"

using namespace Plan9;
using namespace Plan9::Common;
using namespace Plan9::FidMgr;

/*
 * destructively encrypt the buffer, which
 * must be at least 8 characters long.
 */
int
Plan9::Security::P9Any::encrypt9p(void *key, void *vbuf, int n)
{
	char ekey[128], *buf;
	int i, r;

        char *recast_key  = reinterpret_cast<char *>(key);
        char *recast_vbuf = reinterpret_cast<char *>(vbuf);

	if(n < 8)
		return 0;
	m_Des.key_setup(recast_key, ekey);
	buf = recast_vbuf;
	n--;
	r = n % 7;
	n /= 7;
	for(i = 0; i < n; i++){
		m_Des.block_cipher(ekey, buf, 0);
		buf += 7;
	}
	if(r)
		m_Des.block_cipher(ekey, buf - 7 + r, 0);
	return 1;
}

/*
 * destructively decrypt the buffer, which
 * must be at least 8 characters long.
 */
int
Plan9::Security::P9Any::decrypt9p(void *key, void *vbuf, int n)
{
	char ekey[128], *buf;
	int i, r;

        char *recast_key  = reinterpret_cast<char *>(key);
        char *recast_vbuf = reinterpret_cast<char *>(vbuf);

	if(n < 8)
		return 0;
	m_Des.key_setup(recast_key, ekey);
	buf = recast_vbuf;
	n--;
	r = n % 7;
	n /= 7;
	buf += n * 7;
	if(r)
		m_Des.block_cipher(ekey, buf - 7 + r, 1);
	for(i = 0; i < n; i++){
		buf -= 7;
		m_Des.block_cipher(ekey, buf, 1);
	}
	return 1;
}

#define	CHAR(x)		*p++ = f->x
#define	SHORT(x)	p[0] = f->x; p[1] = f->x>>8; p += 2
#define	VLONG(q)	p[0] = (q); p[1] = (q)>>8; p[2] = (q)>>16; p[3] = (q)>>24; p += 4
#define	LONG(x)		VLONG(f->x)
#define	STRING(x,n)	memmove(p, f->x, n); p += n

int
Plan9::Security::P9Any::convTR2M(Ticketreq *f, char *ap)
{
	int n;
	uchar *p;

	p = (uchar*)ap;
	CHAR(type);
	STRING(authid, NAMELEN);
	STRING(authdom, DOMLEN);
	STRING(chal, CHALLEN);
	STRING(hostid, NAMELEN);
	STRING(uid, NAMELEN);
	n = p - (uchar*)ap;
	return n;
}

int
Plan9::Security::P9Any::convT2M(Ticket *f, char *ap, char *key)
{
	int n;
	uchar *p;

	p = (uchar*)ap;
	CHAR(num);
	STRING(chal, CHALLEN);
	STRING(cuid, NAMELEN);
	STRING(suid, NAMELEN);
	STRING(key, DESKEYLEN);
	n = p - (uchar*)ap;
	if(key)
		encrypt9p(key, ap, n);
	return n;
}

int
Plan9::Security::P9Any::convA2M(Authenticator *f, char *ap, char *key)
{
	int n;
	uchar *p;

	p = (uchar*)ap;
	CHAR(num);
	STRING(chal, CHALLEN);
	LONG(id);
	n = p - (uchar*)ap;
	if(key)
		encrypt9p(key, ap, n);
	return n;
}

#undef CHAR
#undef SHORT
#undef VLONG
#undef LONG
#undef STRING

#define	CHAR(x)		f->x = *p++
#define	SHORT(x)	f->x = (p[0] | (p[1]<<8)); p += 2
#define	VLONG(q)	q = (p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24)); p += 4
#define	LONG(x)		VLONG(f->x)
#define	STRING(x,n)	memmove(f->x, p, n); p += n

void
Plan9::Security::P9Any::convM2A(char *ap, Authenticator *f, char *key)
{
	uchar *p;

	if(key)
		decrypt9p(key, ap, AUTHENTLEN);
	p = (uchar*)ap;
	CHAR(num);
	STRING(chal, CHALLEN);
	LONG(id);
	USED(p);
}

void
Plan9::Security::P9Any::convM2T(char *ap, Ticket *f, char *key)
{
	uchar *p;

	if(key)
		decrypt9p(key, ap, TICKETLEN);
	p = (uchar*)ap;
	CHAR(num);
	STRING(chal, CHALLEN);
	STRING(cuid, NAMELEN);
	f->cuid[NAMELEN-1] = 0;
	STRING(suid, NAMELEN);
	f->suid[NAMELEN-1] = 0;
	STRING(key, DESKEYLEN);
	USED(p);
}

#undef CHAR
#undef SHORT
#undef LONG
#undef VLONG
#undef STRING

int
Plan9::Security::P9Any::passtokey(char *key, char *p)
{
	uchar buf[NAMELEN], *t;
	int i, n;

	n = strlen(p);
	if(n >= NAMELEN)
		n = NAMELEN-1;
	memset(buf, ' ', 8);
	t = buf;
	strncpy((char*)t, p, n);
	t[n] = 0;
	memset(key, 0, DESKEYLEN);
	for(;;){
		for(i = 0; i < DESKEYLEN; i++)
			key[i] = (t[i] >> i) + (t[i+1] << (8 - (i+1)));
		if(n <= 8)
			return 1;
		n -= 8;
		t += 8;
		if(n < 8){
			t -= 8 - n;
			n = 8;
		}
		encrypt9p(key, t, 8);
	}
	return 1;	/* not reached */
}

char authkey[DESKEYLEN];
char *authid;
char *authdom;
char *haveprotosmsg;
char *needprotomsg;

void
Plan9::Security::P9Any::MakeInitCall(void)
{
	int n, fd;
	char abuf[200];
	char *f[4];
        std::string af;

	af = Plan9::Common::autharg;
	if(af.empty())
		af = "/etc/u9fs.key";

	if((fd = open(af.c_str(), OREAD)) < 0)
		Logging::sysfatal("can't open key file '%s'", af.c_str());

	if((n = m_transport->readn(fd, abuf, sizeof(abuf)-1)) < 0)
		Logging::sysfatal("can't read key file '%s'", af.c_str());
	close(fd);
	if (n > 0 && abuf[n - 1] == '\n')
		n--;
	abuf[n] = '\0';

	if(Logging::getfields(abuf, f, nelem(f), 0, "\n") != 3)
		Logging::sysfatal("key file '%s' not exactly 3 lines", af.c_str());

	passtokey(authkey, f[0]);
	authid = strdup(f[1]);
	authdom = strdup(f[2]);
	haveprotosmsg = Logging::smprint("p9sk1@%s", authdom);
	needprotomsg = Logging::smprint("p9sk1 %s", authdom);
	if(haveprotosmsg == NULL || needprotomsg == NULL)
		Logging::sysfatal("out of memory");
}

char*
Plan9::Security::P9Any::MakeAuthCall(Fcall *rx, Fcall *tx)
{
	AuthSession *sp;
	FidMgr::Fid *f;
	char *ep;

	sp = reinterpret_cast<AuthSession *>(malloc(sizeof(AuthSession)));
	f = m_FidMgr->newauthfid(rx->afid, sp, &ep);
	if (f == NULL) {
		free(sp);
		return ep;
	}
	if (chatty9p)
		Logging::fprint(2, "p9anyauth: afid %d\n", rx->afid);
	sp->state = HaveProtos;
	sp->uname = strdup(rx->uname);
	sp->aname = strdup(rx->aname);
	tx->aqid.type = QTAUTH;
	tx->aqid.path = 1;
	tx->aqid.vers = 0;
	return NULL;
}

char *
Plan9::Security::P9Any::MakeAttachCall(Fcall *rx, Fcall *tx)
{
	AuthSession *sp;
	Fid *f;
	char *ep;

	f = m_FidMgr->oldauthfid(rx->afid, (void **)&sp, &ep);
	if (f == NULL)
		return ep;
	if (chatty9p)
		Logging::fprint(2, "p9anyattach: afid %d state %d\n", rx->afid, sp->state);
	if (sp->state == Established && strcmp(rx->uname, sp->uname) == 0
		&& strcmp(rx->aname, sp->aname) == 0){
		rx->uname = sp->t.suid;
		return NULL;
	}
	return "authentication failed";
}

int
Plan9::Security::P9Any::readstr(Fcall *rx, Fcall *tx, char *s, int len)
{
	if (rx->offset >= len)
		return 0;
	tx->count = len - rx->offset;
	if (tx->count > rx->count)
		tx->count = rx->count;
	memcpy(tx->data, s + rx->offset, tx->count);
	return tx->count;
}

char *
Plan9::Security::P9Any::MakeReadCall(Fcall *rx, Fcall *tx)
{
	AuthSession *sp;
	char *ep;

	Fid *f;
	f = m_FidMgr->oldauthfid(rx->fid, (void **)&sp, &ep);
	if (f == NULL)
		return ep;
	if (chatty9p)
		Logging::fprint(2, "p9anyread: afid %d state %d\n", rx->fid, sp->state);
	switch (sp->state) {
	case HaveProtos:
		readstr(rx, tx, haveprotosmsg, strlen(haveprotosmsg) + 1);
		if (rx->offset + tx->count == strlen(haveprotosmsg) + 1)
			sp->state = NeedProto;
		return NULL;
	case HaveTreq:
		if (rx->count != TICKREQLEN)
			goto botch;
		convTR2M(&sp->tr, tx->data);
		tx->count = TICKREQLEN;
		sp->state = NeedTicket;
		return NULL;
	case HaveAuth: {
		Authenticator a;
		if (rx->count != AUTHENTLEN)
			goto botch;
		a.num = AuthAs;
		memmove(a.chal, sp->cchal, CHALLEN);
		a.id = 0;
		convA2M(&a, (char*)tx->data, sp->t.key);
		memset(sp->t.key, 0, sizeof(sp->t.key));
		tx->count = rx->count;
		sp->state = Established;
		return NULL;
	}
	default:
	botch:
		return "protocol botch";
	}
}

char *
Plan9::Security::P9Any::MakeWriteCall(Fcall *rx, Fcall *tx)
{
	AuthSession *sp;
	char *ep;

	Fid *f;

	f = m_FidMgr->oldauthfid(rx->fid, (void **)&sp, &ep);
	if (f == NULL)
		return ep;
	if (chatty9p)
		Logging::fprint(2, "p9anywrite: afid %d state %d\n", rx->fid, sp->state);
	switch (sp->state) {
	case NeedProto:
		if (rx->count != strlen(needprotomsg) + 1)
			return "protocol response wrong length";
		if (memcmp(rx->data, needprotomsg, rx->count) != 0)
			return "unacceptable protocol";
		sp->state = NeedChal;
		tx->count = rx->count;
		return NULL;
	case NeedChal:
		if (rx->count != CHALLEN)
			goto botch;
		memmove(sp->cchal, rx->data, CHALLEN);
		sp->tr.type = AuthTreq;
		safecpy(sp->tr.authid, authid, sizeof(sp->tr.authid));
		safecpy(sp->tr.authdom, authdom, sizeof(sp->tr.authdom));
		randombytes((uchar *)sp->tr.chal, CHALLEN);
		safecpy(sp->tr.hostid, "", sizeof(sp->tr.hostid));
		safecpy(sp->tr.uid, "", sizeof(sp->tr.uid));
		tx->count = rx->count;
		sp->state = HaveTreq;
		return NULL;
	case NeedTicket: {
		Authenticator a;

		if (rx->count != TICKETLEN + AUTHENTLEN) {
			Logging::fprint(2, "bad length in attach");
			goto botch;
		}
		convM2T((char*)rx->data, &sp->t, authkey);
		if (sp->t.num != AuthTs) {
			Logging::fprint(2, "bad AuthTs in attach\n");
			goto botch;
		}
		if (memcmp(sp->t.chal, sp->tr.chal, CHALLEN) != 0) {
			Logging::fprint(2, "bad challenge in attach\n");
			goto botch;
		}
		convM2A((char*)rx->data + TICKETLEN, &a, sp->t.key);
		if (a.num != AuthAc) {
			Logging::fprint(2, "bad AuthAs in attach\n");
			goto botch;
		}
		if(memcmp(a.chal, sp->tr.chal, CHALLEN) != 0) {
			Logging::fprint(2, "bad challenge in attach 2\n");
			goto botch;
		}
		sp->state = HaveAuth;
		tx->count = rx->count;
		return NULL;
	}
	default:
	botch:
		return "protocol botch";
	}
}

void
Plan9::Security::P9Any::safefree(char *p)
{
	if (p) {
		memset(p, 0, strlen(p));
		free(p);
	}
}

char *
Plan9::Security::P9Any::MakeClunkCall(Fcall *rx, Fcall *tx)
{
	Fid *f;
	AuthSession *sp;
	char *ep;

	f = m_FidMgr->oldauthfid(rx->fid, (void **)&sp, &ep);
	if (f == NULL)
		return ep;
	if (chatty9p)
		Logging::fprint(2, "p9anyclunk: afid %d\n", rx->fid);
	safefree(sp->uname);
	safefree(sp->aname);
	memset(sp, 0, sizeof(*sp));
	free(sp);
	return NULL;
}
