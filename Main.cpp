#include "Server.h"
#include "Logging.h"
#include "Users.h"
#include "P9Any.h"
#include "AuthNone.h"
#include "AuthRHosts.h"

// Replace these with your derived classes
// #include "ITransport.h"
// #include "IFileSystemUserOps.h"
// #include "StdinTransport.h"
#include "TCPTransport.h"
#include "PosixUserOps.h"

using namespace Plan9;
using namespace Plan9::Common;
using namespace Plan9::Transport;
using namespace Plan9::Server;

char   *Plan9::Common::logfile = NULL;
int     Plan9::Common::chatty9p = 0;
char   *Plan9::Common::autharg = NULL;
ulong   Plan9::Common::msize = IOHDRSZ+8192;
int     Plan9::Common::network = 1;
char   *Plan9::Common::defaultuser = NULL;
char    Plan9::Common::hostname[256];
char    Plan9::Common::remotehostname[256];
char   *Plan9::Common::root = NULL;
int     Plan9::Common::old9p = -1;

static char defaultLogName[]="/tmp/u9fs.log";

#define DEFAULT_PORT 564

void
usage(void)
{
    Logging::fprint(2, "usage: u9fs [-Dnz] [-p port] [-a authmethod] [-m msize] [-u user] [root]\n");
    exit(1);
}

int
main(int argc, char **argv)
{
    char *authtype;
    uint i;
    int fd;
    int logflag;
    extern char *optarg;
    int port=-1;
    long tempPort; // Ignored

    logfile = defaultLogName;

    // Check for port override on command line before doing anything else
    if (-1 != getopt(argc, argv, ":p:"))
    {
        char *portStr = optarg;

        if (NULL != portStr)
        {
            if (':' == *portStr || ('0' > *portStr || '9' < *portStr))
            {
                Logging::sysfatal("Port number missing or illegal value (%s) supplied", portStr);
                return(-1);
            }
            else
            {
                port = atoi(portStr);
                Logging::fprint(2, "Default port overridden with %d\n", port);
            }
        }
        else
        {
            Logging::sysfatal("Port option (-p) requires port number");
            return(-1);
        }
    }
    else
    {
        port = DEFAULT_PORT;
        Logging::fprint(2, "No port specified -- using default of %d\n", port);
    }

    P9Users                 *users = new P9Users();
    // ITransport          *transport = new StdinTransport(0, 1);
    ITransport          *transport = new TCPTransport(port);
    // IFileSystemUserOps    *userOps = new PosixUserOps(users);
    PosixUserOps    *userOps = new PosixUserOps(users);
    
    IAuth *authmethods[3];

    authmethods[0] = new Plan9::Security::RHostsAuth(std::string("rhosts"), users, (IFileSystemUserOps*)userOps, transport);
    authmethods[1] = new Plan9::Security::P9Any("p9any", users, (IFileSystemUserOps*)userOps, transport);
    authmethods[2] = new Plan9::Security::AuthNone("none", users, (IFileSystemUserOps*)userOps, transport);

    IAuth *auth = authmethods[0];

    logflag = O_WRONLY|O_APPEND|O_CREAT;
    ARGBEGIN{
    case 'D':
        chatty9p = 1;
        break;
    case 'a':
        authtype = EARGF(usage());
        auth = NULL;
        for(i=0; i<nelem(authmethods); i++)
            if(strcmp(authmethods[i]->GetName(), authtype)==0)
                auth = authmethods[i];
        if(auth == NULL)
            Logging::sysfatal("unknown auth type '%s'", authtype);
        break;
    case 'A':
        autharg = EARGF(usage());
        break;
    case 'l':
        logfile = EARGF(usage());
        break;
    case 'm':
        msize = strtol(EARGF(usage()), 0, 0);
        break;
    case 'p':
        tempPort = strtol(EARGF(usage()), 0, 0);
        break;
    case 'n':
        network = 0;
        break;
    case 'u':
        defaultuser = EARGF(usage());
        break;
    case 'z':
        logflag |= O_TRUNC;
    }ARGEND

    if(argc > 1)
        usage();

    fd = open(logfile, logflag, 0666);
    if(fd < 0)
        Logging::sysfatal("cannot open log '%s'", logfile);

    if(fd != 2){
        if(dup2(fd, 2) < 0)
            Logging::sysfatal("cannot dup fd onto stderr");
        close(fd);
    }
    Logging::fprint(2, "u9fs\nkill %d\n", (int)getpid());

    fmtinstall('F', fcallconv);
    fmtinstall('D', dirconv);
    fmtinstall('M', dirmodeconv);

    transport->rxbuf = reinterpret_cast<p9uchar *>(emalloc(msize));
    transport->txbuf = reinterpret_cast<p9uchar *>(emalloc(msize));
    transport->databuf = emalloc(msize);

    auth->MakeInitCall();

    if(network)
        transport->getremotehostname(remotehostname, sizeof remotehostname);

    if(gethostname(hostname, sizeof hostname) < 0)
        strcpy(hostname, "gnot");

    umask(0);

    if(argc == 1)
        root = argv[0];

    none = users->uname2user("none");

    P9Server *theServer = new P9Server(transport, (IFileSystemUserOps*)userOps, users);

    theServer->serve();

    return 0;
}
