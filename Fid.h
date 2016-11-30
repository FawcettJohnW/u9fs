#ifndef __P9FID_H_
#define __P9FID_H_
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include "Users.h"
#include "IFileSystemUserOps.h"
#include "Logging.h"

static char    Efidactive[] = "fid already in use";
static char    Ebadfid[] =     "fid unknown or out of range";

namespace Plan9
{
    namespace FileSystem
    {
        class IFileSystemUserOps;
    }
}

namespace Plan9
{
    namespace FidMgr
    {
        class Fid
        {
            friend class FidMgr;

            public:
                Fid( void ) 
                : fid(-1), path(NULL), u(NULL), omode(-1), dir(NULL), diroffset(-1), fd(-1),
                  dirent(NULL), direof(-1), next(NULL), prev(NULL), auth(0), authmagic(NULL),
                  linkPath(NULL)
                {};
                virtual ~Fid( void ) {};

                int fid;
                char *path;
                struct stat st;
                Plan9::P9UserMgmt::P9User *u;
                int omode;
                DIR *dir;
                int diroffset;
                int fd;
                struct dirent *dirent;
                int direof;
                Fid *next;
                Fid *prev;
                int auth;
                void *authmagic;
                char *linkPath;
        }; // Class Fid

        class FidMgr
        {
            public:
                FidMgr( Plan9::P9UserMgmt::P9Users *p9Users, Plan9::FileSystem::IFileSystemUserOps *UsrOps )
                : m_UsrMgr(p9Users), m_UsrOps(UsrOps)
                {};
                virtual ~FidMgr() {};

                Fid* lookupfid(int fid);
                Fid* newfid(int fid, char **ep);
                Fid* newauthfid(int fid, void *magic, char **ep);
                Fid* oldfidex(int fid, int auth, char **ep);
                Fid* oldfid(int fid, char **ep);
                Fid* oldauthfid(int fid, void **magic, char **ep);
                void freefid(Fid *f);
                int  fidstat(Fid *fid, char **ep);

            private:
                 Fid *fidtab[300];

                 Plan9::P9UserMgmt::P9Users *m_UsrMgr;
                 Plan9::FileSystem::IFileSystemUserOps *m_UsrOps;

        }; // Class FidMgr
    } // Namespace Fid
} // Namespace Plan9

#endif // __P9FID_H_
