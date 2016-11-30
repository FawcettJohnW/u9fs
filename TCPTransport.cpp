#include "TCPTransport.h"
#include "Logging.h"

#include <sys/types.h>
#include <sys/socket.h> /* various networking crud */
#include <sys/ioctl.h> /* various networking crud */
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <memory>
#include <algorithm>

using namespace Plan9;
using namespace Plan9::Common;
using namespace Plan9::Fcalls;
using namespace Plan9::Transport;

struct TCPThreadWrapper {
    char * msg;
    Plan9::Transport::TCPTransport *theObject;

    TCPThreadWrapper( char* m, Plan9::Transport::TCPTransport* f ) : msg(m), theObject(f) {}
};

extern "C" void* call_acceptor( void *f )
{
    std::auto_ptr< TCPThreadWrapper > w( static_cast< TCPThreadWrapper* >( f ) );
    w->theObject->TCPAcceptor(w->msg);

    return 0;
}

extern "C" void* call_listener( void *f )
{
    std::auto_ptr< TCPThreadWrapper > w( static_cast< TCPThreadWrapper* >( f ) );
    w->theObject->TCPListener(w->msg);

    return 0;
}

void *TCPTransport::TCPAcceptor( void *threadArgs )
{
    // Bind to the incoming port
    struct sockaddr_in server_address;

    m_serverSock = socket(AF_INET, SOCK_STREAM, 0);

    if (0 < m_serverSock)
    {
        int on = 1;
        int iStat;
        iStat = setsockopt(m_serverSock, SOL_SOCKET,  SO_REUSEADDR, (char *)&on, sizeof(on));
        if (iStat < 0)
        {
            tcpSysFatal(m_serverSock, "TCP Transport:  Could not set socket to resue address");
            exit(-1);
        }

        memset(&server_address, 0, sizeof(server_address));
        server_address.sin_family = AF_INET;
        server_address.sin_addr.s_addr = INADDR_ANY;
        server_address.sin_port = htons(m_Port);

        if (0 < bind(m_serverSock, (struct sockaddr *)&server_address, sizeof (server_address)))
        {
            tcpSysFatal(m_serverSock, "TCP Transport:  Could not bind to port %d", m_Port);
            exit(-1);
        }

        listen(m_serverSock, 15);

        while (1)
        {
            // The user will send a signal to kill the service, which will not be caught, and break this loop
            int acceptSock = 0;
            fd_set fdSet;
            FD_ZERO(&fdSet);
            FD_SET(m_serverSock, &fdSet);

            acceptSock = accept(m_serverSock, NULL, NULL);
            if (acceptSock > 0)
            {
                AddNewListener(acceptSock);
            }
        }
        Logging::fprint(2, "TCPAcceptor has broken accept loop -- Errno is %d (%s)\n", errno, strerror(errno));
    }
    else
    {
        tcpSysFatal(-1, "TCP Transport:  Could not create server socket");
        exit(-1);
    }

    Logging::fprint(2, "TCPAcceptor no longer accepting connections -- connector thread terminating...\n");
}

bool isInvalidSocket(const int sock)
{
    return sock == -1;
}

void *TCPTransport::TCPListener( void *threadArgs )
{
    // All this does is listen on all the sockets, read the messages in, and drop them into a queue.

    // The user will send a signal to kill the service, which will not be caught, and break this loop
    while (1)
    {
        // Timeout twice a second
        int timeout = 500;  // Milliseconds

        pollfd *allFds = new pollfd[m_socketList.size()];

        memset(allFds, 0, sizeof(allFds));
        bool invalidatedOne = false;
        size_t numFds = 0;
        pthread_mutex_lock(&m_queueLock);
        for (size_t i = 0; i < m_socketList.size(); i++)
        {
            if (m_socketList[i] != -1)
            {
                allFds[numFds].fd = m_socketList[i];
                allFds[numFds].events = POLLIN;
                numFds++;
            }
            else
            {
                invalidatedOne = true;
            }
        }
        pthread_mutex_unlock(&m_queueLock);

        if (numFds <= 0)
        {
            // No valid FDs at this time...
            sleep(1);
            continue;
        }

        int pollStat = poll(allFds, numFds, timeout);

        pthread_mutex_lock(&m_queueLock);
        for (size_t i = 0; i < numFds; i++)
        {
            if (allFds[i].revents == 0)
            {
                // Nothing on this one
                continue;
            }
            else if (allFds[i].revents != POLLIN)
            {
                Logging::fprint(2, "Bad poll event on socket %d.  Closing\n", allFds[i].fd);
                if (!invalidatedOne)
                {
                    m_socketList[i] = -1;
                }
                else
                {
                    for (size_t i = 0; i < m_socketList.size(); i++)
                    {
                        if (m_socketList[i] == allFds[i].fd)
                        {
                            m_socketList[i] = -1;
                            break;
                        }
                    }
                }
                invalidatedOne = true;
            }
            else
            {
                fcallMessage *fcm = new fcallMessage();
                Fcall *fc = new Fcall();

                fcm->sock = allFds[i].fd;
                fcm->fc   = fc;

                if(old9p == 1)
                {
                    getfcallold(allFds[i].fd, fc, 0);
                }
                else if(old9p == 0)
                {
                    getfcallnew(allFds[i].fd, fc, 0);
                }
                else
                {
                    /* auto-detect */
                    if(readn(allFds[i].fd, rxbuf, 3) != 3)
                    {
                        tcpSysFatal(allFds[i].fd, "couldn't read message");
                    }
                    else
                    {
                        /* is it an old (9P1) message? */
                        if(50 <= rxbuf[0] && rxbuf[0] <= 87 && (rxbuf[0]&1)==0 && GBIT16(rxbuf+1) == 0xFFFF)
                        {
                            old9p = 1;
                            getfcallold(allFds[i].fd, fc, 3);
                        }
                        else
                        {
                            getfcallnew(allFds[i].fd, fc, 3);
                            old9p = 0;
                        }
                    }
                }

                m_messageQueue.push(fcm);

                sem_post(&m_semaphore);
            }

            if (invalidatedOne)
            {
                int invalidSocket = -1;
                m_socketList.erase(std::remove_if(m_socketList.begin(), m_socketList.end(),
                                                  isInvalidSocket),
                                                  m_socketList.end());
            }
        }
        pthread_mutex_unlock(&m_queueLock);
    }
}

// Constructor
TCPTransport::TCPTransport(int Port) : ITransport(Port)
{
    static char acceptName[] = "Acceptor";
    static char listenName[] = "Listener";

    m_Running = 1;

    pthread_mutexattr_t attrs;
    pthread_mutexattr_init(&attrs);
    pthread_mutexattr_settype(&attrs, PTHREAD_MUTEX_RECURSIVE);

    pthread_mutex_init(&m_queueLock, &attrs);
    sem_init(&m_semaphore, 0, 0);

    // Start the acceptor
    pthread_attr_t AcceptorAttr;
    pthread_attr_init(&AcceptorAttr);
    TCPThreadWrapper *acceptorWrapper = new TCPThreadWrapper(acceptName, this);
    if (0 != pthread_create(&m_AcceptorThread, &AcceptorAttr, call_acceptor, acceptorWrapper))
    {
        tcpSysFatal(-1, "Cannot create acceptor thread -- Error is %d (%s)\n", errno, strerror(errno));
        exit(-1);
    }

    // Start the listener
    pthread_attr_t ListenerAttr;
    pthread_attr_init(&ListenerAttr);
    TCPThreadWrapper *listenerWrapper = new TCPThreadWrapper(listenName, this);
    if (0 != pthread_create(&m_ListenerThread, &ListenerAttr, call_listener, listenerWrapper))
    {
        tcpSysFatal(-1, "Cannot create listener thread -- Error is %d (%s)\n", errno, strerror(errno));
        exit(-1);
    }
}

// Destructor
TCPTransport::~TCPTransport( void )
{
    m_Running = 0;

    // Wait for the acceptor and listener to exit
    pthread_join(m_AcceptorThread, NULL);
    pthread_join(m_ListenerThread, NULL);
}

void
Plan9::Transport::TCPTransport::getfcallnew(int fd, Fcall *fc, uint have)
{
Logging::fprint(2, "getfcallnew entry\n");
    uint len;

    if(have > BIT32SZ)
    {
        tcpSysFatal(fd, "cannot happen");
                return;
    }

Logging::fprint(2, "have (%d) is < BIT32SZ (%d)\n", have, BIT32SZ);
    if(have < BIT32SZ && readn(fd, rxbuf+have, BIT32SZ-have) != BIT32SZ-have)
    {
        tcpSysFatal(fd, "couldn't read message");
                return;
    }

Logging::fprint(2, "Read in message\n");
    len = GBIT32(rxbuf);
Logging::fprint(2, "Got length.  Is is %d\n", len);
    if(len <= BIT32SZ)
    {
        tcpSysFatal(fd, "bogus message");
                return;
    }

Logging::fprint(2, "Adjusting length\n");
    len -= BIT32SZ;
Logging::fprint(2, "New length is %d\n", len);
    if(readn(fd, rxbuf+BIT32SZ, len) != len)
    {
        tcpSysFatal(fd, "short message");
                return;
    }

Logging::fprint(2, "Converting...\n");
    if(convM2S(rxbuf, len+BIT32SZ, fc) != len+BIT32SZ)
    {
        tcpSysFatal(fd, "getfcallnew:  badly sized message type %d", rxbuf[0]);
                return;
    }
Logging::fprint(2, "Conversion completed...\n");
}

void
Plan9::Transport::TCPTransport::getfcallold(int fd, Fcall *fc, uint have)
{
Logging::fprint(2, "getfcallold entry\n");
    uint len, n;

    if(have > 3)
    {
        tcpSysFatal(fd, "cannot happen");
                return;
    }

    if(have < 3 && readn(fd, rxbuf, 3-have) != 3-have)
    {
        tcpSysFatal(fd, "couldn't read message");
                return;
    }

    len = oldhdrsize(rxbuf[0]);
    if(len < 3)
    {
        tcpSysFatal(fd, "bad message %d", rxbuf[0]);
                return;
    }
    if(len > 3 && readn(fd, rxbuf+3, len-3) != len-3)
    {
        tcpSysFatal(fd, "couldn't read message");
                return;
    }

    n = iosize(rxbuf);
    if(readn(fd, rxbuf+len, n) != n)
    {
        tcpSysFatal(fd, "couldn't read message");
                return;
    }
    len += n;

    if(convM2Sold(rxbuf, len, fc) != len)
    {
        tcpSysFatal(fd, "convM2Sold: badly sized message type %d", rxbuf[0]);
                return;
    }
}

void
Plan9::Transport::TCPTransport::putfcallnew(int fd, Fcall *tx)
{
Logging::fprint(2, "putfcallnew entry\n");
    uint n;

    if((n = convS2M(tx, txbuf, msize)) == 0)
    {
        tcpSysFatal(m_currentSock, "couldn't format message type %d", tx->type);
                return;
    }
    if(write(fd, txbuf, n) != n)
    {
        tcpSysFatal(m_currentSock, "couldn't send message");
                return;
    }
}

void
Plan9::Transport::TCPTransport::putfcallold(int fd, Fcall *tx)
{
    uint n;
Logging::fprint(2, "putfcallold entry\n");

    if((n = convS2Mold(tx, txbuf, msize)) == 0)
    {
        tcpSysFatal(m_currentSock, "couldn't format message type %d", tx->type);
                return;
    }
    if(write(m_currentSock, txbuf, n) != n)
    {
        tcpSysFatal(fd, "couldn't send message");
                return;
    }
}

void
Plan9::Transport::TCPTransport::getfcall(int *fd, Fcall *fc)
{
misfired_semaphore:
        sem_wait(&m_semaphore);
        pthread_mutex_lock(&m_queueLock);

        if (m_messageQueue.empty())
        {
            pthread_mutex_unlock(&m_queueLock);
            goto misfired_semaphore;
        }

        fcallMessage *fcm = m_messageQueue.front();
        m_messageQueue.pop();
        pthread_mutex_unlock(&m_queueLock);

        *fd = fcm->sock;
        Fcall *localfc = fcm->fc;

        // Copy, since we own this memory
        fc->type = localfc->type;
        fc->fid = localfc->fid;
        fc->tag = localfc->tag;
        fc->msize = localfc->msize;
        fc->version = localfc->version;
        fc->oldtag = localfc->oldtag;
        fc->ename = localfc->ename;
        fc->iounit = localfc->iounit;
        fc->uname = localfc->uname;
        fc->aname = localfc->aname;
        fc->perm = localfc->perm;
        fc->name = localfc->name;
        fc->mode = localfc->mode;
        fc->extension = localfc->extension;
        fc->newfid = localfc->newfid;
        fc->nwname = localfc->nwname;
        memcpy(fc->wname, localfc->wname, MAXWELEM);
        fc->nwqid = localfc->nwqid;
        memcpy(fc->wqid, localfc->wqid, MAXWELEM);
        fc->offset = localfc->offset;
        fc->count = localfc->count;
        fc->data = localfc->data;
        fc->nstat = localfc->nstat;
        fc->stat = localfc->stat;
        fc->afid = localfc->afid;
        fc->n_uname = localfc->n_uname;

        delete localfc;
        delete fcm;
}

long
Plan9::Transport::TCPTransport::readn(int f, void *av, long n)
{
    char *a;
    long m, t;

    a = reinterpret_cast<char *>(av);
    t = 0;
    while(t < n){
        m = recv(f, a+t, n-t, MSG_WAITALL);
        if(m <= 0){
            if(t == 0)
                return m;
            break;
        }
        t += m;
    }
    return t;
}

void
Plan9::Transport::TCPTransport::getremotehostname(char *name, int nname)
{
        struct sockaddr_in sock;
        struct hostent *hp;
        uint len;
        int on;
        static char unknown[]="unknown";

        Logging::strecpy(name, name+nname, unknown);
        len = sizeof sock;
        if(getpeername(0, (struct sockaddr*)&sock, (socklen_t*)&len) < 0)
                return;

        hp = gethostbyaddr((char *)&sock.sin_addr, sizeof (struct in_addr),
                sock.sin_family);
        if(hp == 0)
                return;

        Logging::strecpy(name, name+nname, hp->h_name);
        on = 1;
        setsockopt(0, SOL_SOCKET, SO_KEEPALIVE, (char*)&on, sizeof(on));

        on = 1;
        setsockopt(0, IPPROTO_TCP, TCP_NODELAY, (char*)&on, sizeof(on));
}

void
Plan9::Transport::TCPTransport::tcpSysFatal(int fd, const char *fmt, ...)
{
        char buf[1024];
        va_list va, temp;

Logging::fprint(2, "tcpSysFatal entry\n");
        va_start(va, fmt);
        va_copy(temp, va);
        Plan9::Conversion::doprint(buf, buf+sizeof buf, fmt, &temp);
        va_end(temp);
        va_end(va);
        Logging::fprint(2, "u9fs: %s\n", buf);
        Logging::fprint(2, "last unix error: %s\n", strerror(errno));

        if (fd > 0)
        {
            pthread_mutex_lock(&m_queueLock);
            int localSock = fd;
            std::vector<int>::iterator sockIter = m_socketList.begin();
            while (sockIter != m_socketList.end())
            {
                if (*sockIter == fd)
                {
                    m_socketList.erase(sockIter);
                    break;
                }
            }
            close(fd);
            pthread_mutex_unlock(&m_queueLock);
        }
}
