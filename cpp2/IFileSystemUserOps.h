#ifndef __P9IFILESYSTEM_H_
#define __P9IFILESYSTEM_H_

#include "P9Common.h"
#include "Logging.h"
#include "Users.h"
// #include "Fid.h"


namespace Plan9
{
    namespace FidMgr
    {
        class Fid;
    }
}

namespace Plan9
{
    namespace FileSystem
    {
        /*
         * frogs: characters not valid in plan9
         * filenames, keep this list in sync with
         * /sys/src/9/port/chan.c:1656
         */
        class IFileSystemUserOps
        {
            public:
                IFileSystemUserOps( Plan9::P9UserMgmt::P9Users *Users )
                : m_P9Users(Users)
                {}

                 virtual ~IFileSystemUserOps( void ) {};

                 virtual int userchange(Plan9::P9UserMgmt::P9User *u, char **ep) = 0;
                
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
                 virtual int groupchange(Plan9::P9UserMgmt::P9User *u, Plan9::P9UserMgmt::P9User *g, char **ep) = 0;
                
                /*
                 * An attempt to enforce permissions by looking at the 
                 * file system.  Separation of checking permission and
                 * actually performing the action is a terrible idea, of 
                 * course, so we use setreuid for most of the permission
                 * enforcement.  This is here only so we can give errors
                 * on open(ORCLOSE) in some cases.
                 */
                 virtual int userperm(Plan9::P9UserMgmt::P9User *u, char *path, int type, int need) = 0;
                 virtual int userwalk(Plan9::P9UserMgmt::P9User *u, char **path, char *elem, Plan9::Common::Qid *qid, char **ep) = 0;
                 virtual int useropen(Plan9::FidMgr::Fid *fid, int omode, char **ep) = 0;
                 virtual int usercreate(Plan9::FidMgr::Fid *fid, char *elem, int uid, int gid, int omode, long perm, char **ep) = 0;
                 virtual int userremove(Plan9::FidMgr::Fid *fid, char **ep) = 0;

                 virtual char* rootpath(char* path) = 0;

                 virtual Plan9::Common::Qid stat2qid(struct stat *st) = 0;
                 virtual void               stat2dir(char *path, struct stat *st, Plan9::Common::Dir *d) = 0;

                 virtual ulong plan9mode(struct stat *st) = 0;

                 virtual char * enfrog(char *src) = 0;
                 virtual char * defrog(char *s) = 0;
 
                 Plan9::P9UserMgmt::P9Users *m_P9Users;

                 virtual int    doStat(const char *path, struct stat *buf) = 0;
        }; // Class IFileSystem
    } // Namespace FileSystem
} // Namespace Plan9
#endif // __P9IFILESYSTEM_H_
