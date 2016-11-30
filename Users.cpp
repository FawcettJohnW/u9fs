#include "Users.h"

using namespace Plan9;
using namespace Plan9::Common;

P9UserMgmt::P9User*
P9UserMgmt::P9Users::adduser(const struct passwd *p)
{
	P9UserMgmt::P9User *u(new P9UserMgmt::P9User());

	u->id = p->pw_uid;
	u->name = estrdup(p->pw_name);
	u->next = GetUtabEntry(p->pw_uid%GetNumUtab());
	u->defaultgid = p->pw_gid;
	SetUtabEntry(p->pw_uid%GetNumUtab(), u);
	return u;
}

int
P9UserMgmt::P9Users::useringroup(P9UserMgmt::P9User *u, P9UserMgmt::P9User *g)
{
	int i;

	for(i=0; i<g->nmem; i++)
		if(strcmp(g->mem[i], u->name) == 0)
			return 1;

	/*
	 * Hack around common Unix problem that everyone has
	 * default group "user" but /etc/group lists no members.
	 */
	if(u->defaultgid == g->id)
		return 1;
	return 0;
}

P9UserMgmt::P9User*
P9UserMgmt::P9Users::addgroup(struct group *g)
{
	P9UserMgmt::P9User *u(new P9UserMgmt::P9User());
	char **p;
	int n;

	n = 0;
	for(p=g->gr_mem; *p; p++)
		n++;
	u->mem = reinterpret_cast<char **>(emalloc(sizeof(u->mem[0])*n));
	n = 0;
	for(p=g->gr_mem; *p; p++)
		u->mem[n++] = estrdup(*p);
	u->nmem = n;
	u->id = g->gr_gid;
	u->name = estrdup(g->gr_name);
	u->next = GetGtabEntry(g->gr_gid%GetNumGtab());
	SetGtabEntry(g->gr_gid%GetNumGtab(), u);
	return u;
}

P9UserMgmt::P9User*
P9UserMgmt::P9Users::uname2user(const char *name)
{
	int i;
	P9UserMgmt::P9User *u;
	struct passwd *p;

	for(i=0; i<GetNumUtab(); i++)
		for(u=GetUtabEntry(i); u; u=u->next)
			if(strcmp(u->name, name) == 0)
				return u;

	if((p = getpwnam(name)) == NULL)
		return NULL;
	return adduser(p);
}

P9UserMgmt::P9User*
P9UserMgmt::P9Users::uid2user(uid_t id)
{
	P9UserMgmt::P9User *u;
	struct passwd *p;

	for(u=GetUtabEntry(id%GetNumUtab()); u; u=u->next)
		if(u->id == id)
			return u;

	if((p = getpwuid(id)) == NULL)
		return NULL;
	return adduser(p);
}

P9UserMgmt::P9User*
Plan9::P9UserMgmt::P9Users::gname2user(char *name)
{
	int i;
	P9UserMgmt::P9User *u;
	struct group *g;

	for(i=0; i<GetNumGtab(); i++)
		for(u=GetGtabEntry(i); u; u=u->next)
			if(strcmp(u->name, name) == 0)
				return u;

	if((g = getgrnam(name)) == NULL)
		return NULL;
	return addgroup(g);
}

P9UserMgmt::P9User*
P9UserMgmt::P9Users::gid2user(gid_t id)
{
	P9UserMgmt::P9User *u;
	struct group *g;

	for(u=GetGtabEntry(id%GetNumGtab()); u; u=u->next)
		if(u->id == id)
			return u;

	if((g = getgrgid(id)) == NULL)
		return NULL;
	return addgroup(g);
}
