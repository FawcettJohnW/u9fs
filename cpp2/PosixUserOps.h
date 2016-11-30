#ifndef __POSIXUSEROPS_H_
#define __POSIXUSEROPS_H_

#include "P9Common.h"
#include "Logging.h"
#include "IFileSystemUserOps.h"
#include "Fid.h"
#include "Users.h"

using namespace Plan9;
using namespace Plan9::Common;
using namespace Plan9::FidMgr;
using namespace Plan9::P9UserMgmt;

namespace Plan9
{
    namespace FileSystem
    {
        class PosixUserOps : public IFileSystemUserOps
        {
            public:
                PosixUserOps( Plan9::P9UserMgmt::P9Users *Users )
                : IFileSystemUserOps(Users)
                {};

                virtual ~PosixUserOps( void );
                

                int userchange(P9User*u, char **ep);
                
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
                int groupchange(P9User*u, P9User*g, char **ep);
                
                /*
                 * An attempt to enforce permissions by looking at the 
                 * file system.  Separation of checking permission and
                 * actually performing the action is a terrible idea, of 
                 * course, so we use setreuid for most of the permission
                 * enforcement.  This is here only so we can give errors
                 * on open(ORCLOSE) in some cases.
                 */
                int userperm(P9User*u, char *path, int type, int need);
                int userwalk(P9User*u, char **path, char *elem, Qid *qid, char **ep);
                int useropen(Fid *fid, int omode, char **ep);
                int usercreate(Plan9::FidMgr::Fid *fid, char *elem, int uid, int gid, int omode, long perm, char **ep);
                int userremove(Fid *fid, char **ep);

                char* rootpath(char* path);

                Qid  stat2qid(struct stat *st);
                void stat2dir(char *path, struct stat *st, Dir *d);

                uchar modebyte(struct stat *st);

                ulong plan9mode(struct stat *st);

                char * enfrog(char *src);
                char * defrog(char *s);

                Plan9::P9UserMgmt::P9Users *m_P9Users;

                int fidstat(Fid *fid, char **ep);
                int doStat(const char *path, struct stat *buf);
        }; // Class PosixUserOps
    } // Namespace FileSystem
} // Namespace Plan9
#endif // __POSIXUSEROPS_H_
