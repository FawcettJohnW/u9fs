#ifndef __P9ANY_H_
#define __P9ANY_H_
/*
 * 4th Edition p9any/p9sk1 authentication based on auth9p1.c
 * Nigel Roles (nigel@9fs.org) 2003
 */

#include "P9Common.h"
#include "IAuth.h"
#include "Fid.h"

namespace Plan9
{
    namespace Security
    {
        class P9Any : public Plan9::Security::IAuth
        {
            friend class IAuth;

            public:
                P9Any(std::string name, Plan9::P9UserMgmt::P9Users* users, Plan9::FileSystem::IFileSystemUserOps* userOps, Plan9::Transport::ITransport* transport)
                   : IAuth(name, users, userOps, transport)
                {
                    m_FidMgr = new Plan9::FidMgr::FidMgr(users, userOps);
                };
                ~P9Any()
                {
                    if (NULL != m_FidMgr)
                        delete m_FidMgr;
                };

                const char * MakeAuthCall(Fcall *rx, Fcall *tx);
                const char * MakeAttachCall(Fcall *rx, Fcall *tx);
                void         MakeInitCall(void);
                const char * MakeReadCall(Fcall *rx, Fcall *tx);
                const char * MakeWriteCall(Fcall *rx, Fcall *tx);
                const char * MakeClunkCall(Fcall *rx, Fcall *tx);

            private:
                // Forward declarations -- see bleow
                struct Ticket;
                struct Authenticator;
                struct Ticketreq;

                int     convT2M(Ticket*, char*, char*);
                void    convM2T(char*, Ticket*, char*);
                void    convM2Tnoenc(char*, Ticket*);

                int     convA2M(Authenticator*, char*, char*);
                void    convM2A(char*, Authenticator*, char*);

                int     convTR2M(Ticketreq*, char*);
                void    convM2TR(char*, Ticketreq*);

                int     passtokey(char*, char*);

                /*
                 * destructively encrypt the buffer, which
                 * must be at least 8 characters long.
                 */
                int encrypt9p(void *key, void *vbuf, int n);

                /*
                 * destructively decrypt the buffer, which
                 * must be at least 8 characters long.
                 */
                int decrypt9p(void *key, void *vbuf, int n);

                int readstr(Fcall *rx, Fcall *tx, char *s, int len);
                void safefree(char *p);

            private:
                char authkey[DESKEYLEN];
                char *authid;
                char *authdom;
                char *haveprotosmsg;
                char *needprotomsg;

                Plan9::FidMgr::FidMgr *m_FidMgr;

                enum {
                        NAMELEN = 28,
                        ERRLEN = 64
                };

                enum
                {
                    DOMLEN=        48,        /* length of an authentication domain name */
                    CHALLEN=    8        /* length of a challenge */
                };

                enum {
                    HaveProtos,
                    NeedProto,
                    NeedChal,
                    HaveTreq,
                    NeedTicket,
                    HaveAuth,
                    Established,
                };

                /* encryption numberings (anti-replay) */
                enum
                {
                    AuthTreq=1,    /* ticket request */
                    AuthChal=2,    /* challenge box request */
                    AuthPass=3,    /* change password */
                    AuthOK=4,    /* fixed length reply follows */
                    AuthErr=5,    /* error follows */
                    AuthMod=6,    /* modify user */
                    AuthApop=7,    /* apop authentication for pop3 */
                    AuthOKvar=9,    /* variable length reply follows */
                    AuthChap=10,    /* chap authentication for ppp */
                    AuthMSchap=11,    /* MS chap authentication for ppp */
                    AuthCram=12,    /* CRAM verification for IMAP (RFC2195 & rfc2104) */
                    AuthHttp=13,    /* http domain login */
                    AuthVNC=14,    /* http domain login */


                    AuthTs=64,    /* ticket encrypted with server's key */
                    AuthTc,        /* ticket encrypted with client's key */
                    AuthAs,        /* server generated authenticator */
                    AuthAc,        /* client generated authenticator */
                    AuthTp,        /* ticket encrypted with client's key for password change */
                    AuthHr        /* http reply */
                };

                struct Ticketreq
                {
                    char    type;
                    char    authid[NAMELEN];    /* server's encryption id */
                    char    authdom[DOMLEN];    /* server's authentication domain */
                    char    chal[CHALLEN];        /* challenge from server */
                    char    hostid[NAMELEN];    /* host's encryption id */
                    char    uid[NAMELEN];        /* uid of requesting user on host */
                };
                #define    TICKREQLEN    (3*NAMELEN+CHALLEN+DOMLEN+1)

                struct Ticket
                {
                    char    num;            /* replay protection */
                    char    chal[CHALLEN];        /* server challenge */
                    char    cuid[NAMELEN];        /* uid on client */
                    char    suid[NAMELEN];        /* uid on server */
                    char    key[DESKEYLEN];        /* nonce DES key */
                };
                #define    TICKETLEN    (CHALLEN+2*NAMELEN+DESKEYLEN+1)

                struct Authenticator
                {
                    char    num;            /* replay protection */
                    char    chal[CHALLEN];
                    ulong    id;            /* authenticator id, ++'d with each auth */
                };
                #define    AUTHENTLEN    (CHALLEN+4+1)

                typedef struct    Ticket        Ticket;
                typedef struct    Ticketreq    Ticketreq;
                typedef struct    Authenticator    Authenticator;

                typedef struct AuthSession {
                    int state;
                    char *uname;
                    char *aname;
                    char cchal[CHALLEN];
                    Ticketreq tr;
                    Ticket t;
                } AuthSession;

        }; // Class p9any
    }  // Namespace Security
} // Namespace Plan9
#endif // __P9ANY_H_
