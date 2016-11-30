#ifndef __P9SERVER_H_
#define __P9SERVER_H_

/* already in plan9.h #include <sys/types.h> *//* for struct passwd, struct group, struct stat ... */
/* plan9.h is first to get the large file support definitions as early as possible */
#include "P9Common.h"
#include <sys/stat.h>	/* for stat, umask */
#include <stdlib.h>	/* for malloc */
#include <string.h>	/* for strcpy, memmove */
#include <pwd.h>	/* for getpwnam, getpwuid */
#include <grp.h>	/* for getgrnam, getgrgid */
#include <unistd.h>	/* for gethostname, pread, pwrite, read, write */
#include <utime.h>	/* for utime */
#include <dirent.h>	/* for readdir */
#include <errno.h>	/* for errno */
#include <stdio.h>	/* for remove [sic] */
#include <fcntl.h>	/* for O_RDONLY, etc. */
#include <limits.h>	/* for PATH_MAX */

#include <sys/socket.h>	/* various networking crud */
#include <netinet/in.h>
#include <netdb.h>

#include "Logging.h"
#include "Users.h"
#include "Fid.h"
#include "Fcall.h"
#include "IFileSystemUserOps.h"
#include "ITransport.h"
#include "P9Any.h"
#include "AuthRHosts.h"
#include "AuthNone.h"

#define S_ISSPECIAL(m) (S_ISCHR(m) || S_ISBLK(m) || S_ISFIFO(m))

using namespace Plan9;
using namespace Plan9::Common;
using namespace Plan9::P9UserMgmt;
using namespace Plan9::FidMgr;
using namespace Plan9::FileSystem;
using namespace Plan9::Transport;
using namespace Plan9::Fcalls;
using namespace Plan9::Security;

namespace Plan9
{
    namespace Server
    {
        static char	Eauth[] =	"authentication failed";
        static char	Ebadfid[] =	"fid unknown or out of range";
        static char	Ebadoffset[] =	"bad offset in directory read";
        static char	Ebadusefid[] =	"bad use of fid";
        static char	Edirchange[] =	"wstat can't convert between files and directories";
        static char	Efidactive[] =	"fid already in use";
        static char	Enotdir[] =	"not a directory";
        static char	Enotowner[] =   "only owner can change group in wstat";
        static char	Especial0[] =	"already attached without access to special files";
        static char	Especial1[] =	"already attached with access to special files";
        static char	Especial[] =	"no access to special file";
        static char	Etoolarge[] =	"i/o count too large";
        static char	Eunknowngroup[] = "unknown group";
        static char	Eunknownuser[] = "unknown user";
        static char	Ewstatbuffer[] = "bogus wstat buffer";

        class P9Server
        {
            public:
                P9Server( ITransport *transport, IFileSystemUserOps *userOps, P9Users *users )
                : m_Transport(transport), m_FileSystemUserOps(userOps), m_P9Users(users)
                {
                    m_FidMgr = new Plan9::FidMgr::FidMgr(users, userOps);
                };
                virtual ~P9Server( void ) {};

                void	rversion(Fcall*, Fcall*);
                void	rauth(Fcall*, Fcall*);
                void	rattach(Fcall*, Fcall*);
                void	rflush(Fcall*, Fcall*);
                void	rclone(Fcall*, Fcall*);
                void	rwalk(Fcall*, Fcall*);
                void	ropen(Fcall*, Fcall*);
                void	rcreate(Fcall*, Fcall*);
                void	rread(Fcall*, Fcall*);
                void	rwrite(Fcall*, Fcall*);
                void	rclunk(Fcall*, Fcall*);
                void	rstat(Fcall*, Fcall*);
                void	rwstat(Fcall*, Fcall*);
                void	rclwalk(Fcall*, Fcall*);
                void	rremove(Fcall*, Fcall*);

                Plan9::Transport::ITransport *m_Transport;
                // void getfcallnew(int fd, Fcall *fc, int have)
                // void getfcallold(int fd, Fcall *fc, int have)
                // void putfcallnew(int wfd, Fcall *tx)
                // void putfcallold(int wfd, Fcall *tx)
                // void getfcall(int fd, Fcall *fc)

                Plan9::FileSystem::IFileSystemUserOps *m_FileSystemUserOps;
                // int	userchange(User*, char**);
                // int	userwalk(User*, char**, char*, Qid*, char**);
                // int	useropen(Fid*, int, char**);
                // int	usercreate(Fid*, char*, int, int, int, long, char**);
                // int	userremove(Fid*, char**);
                // int	userperm(User*, char*, int, int);
                // int	useringroup(User*, User*);
                // int	fidstat(Fid*, char**);
                // int	groupchange(User*, User*, char**);
                // Qid	stat2qid(struct stat*);
                // char* rootpath(char *path)

                Plan9::P9UserMgmt::P9Users *m_P9Users;
                // User*	uname2user(char*);
                // User*	gname2user(char*);
                // User*	uid2user(int);
                // User*	gid2user(int);

                Plan9::FidMgr::FidMgr *m_FidMgr;
                // Fid*	newfid(int, char**);
                // Fid*	oldfidex(int, int, char**);
                // Fid*	oldfid(int, char**);
                // void	freefid(Fid*);

                void seterror(Fcall *f, char *error);

                int	connected;
                int	devallowed;
                int	authed;

                IAuth *auth;

                void serve( void );
                ulong plan9mode(struct stat *st);
                int isowner(P9User *u, Fid *f);

            private:
                /*
                 * this is for chmod, so don't worry about S_IFDIR
                 */
                mode_t unixmode(Dir *d);

                /*
                 * we keep a table by numeric id.  by name lookups happen infrequently
                 * while by-number lookups happen once for every directory entry read
                 * and every stat request.
                 */
                P9User *utab[64];
                P9User *gtab[64];

         }; // Class P9Server
    }  // Namespace Server
} // Namespace Plan9
#endif // __P9SERVER_H_
