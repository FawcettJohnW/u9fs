#ifndef __IAUTH_H
#define __IAUTH_H
#include "P9Common.h"
#include "IDes.h"
#include "Fcall.h"
#include "Logging.h"
#include "Users.h"
#include "IFileSystemUserOps.h"
#include "ITransport.h"

using namespace Plan9;
using namespace Plan9::Common;
using namespace Plan9::Fcalls;
using namespace Plan9::P9UserMgmt;

static char errStr[] = "Not implemented";

namespace Plan9
{
    namespace Security
    {
        class IAuth
        {
            // Forward declaration -- in IProtocol.h
            public:
                typedef char* (authcall)(Fcall*, Fcall*);
                typedef char* (attachcall)(Fcall*, Fcall*);
                typedef void  (initcall)(void);
                typedef char* (readcall)(Fcall*, Fcall*);
                typedef char* (writecall)(Fcall*, Fcall*);
                typedef char* (clunkcall)(Fcall*, Fcall*);

                IAuth(std::string& name, Plan9::P9UserMgmt::P9Users* users, Plan9::FileSystem::IFileSystemUserOps* userOps, Plan9::Transport::ITransport* transport)
                : m_name(name), m_users(users), m_userOps(userOps), m_transport(transport)
                { };

                virtual ~IAuth() {};

                virtual const char * MakeAuthCall(Fcall*, Fcall *) = 0;
                virtual const char * MakeAttachCall(Fcall*, Fcall*) = 0;
                virtual void         MakeInitCall(void) = 0;
                virtual const char * MakeReadCall(Fcall*, Fcall*) = 0;
                virtual const char * MakeWriteCall(Fcall*, Fcall*) = 0;
                virtual const char * MakeClunkCall(Fcall*, Fcall*) = 0;

                const char *GetName( void )
                {
                    return m_name.c_str();
                }

                inline void safecpy(char *to, const char *from, int tolen)
                {
                        int fromlen;
                        memset(to, 0, tolen);
                        fromlen = from ? strlen(from) : 0;
                        if (fromlen > tolen)
                                fromlen = tolen;
                        memcpy(to, from, fromlen);
                }

            private:
                std::string  m_name;

            protected:
                Plan9::Security::IDes                  m_Des;
                Plan9::P9UserMgmt::P9Users            *m_users;
                Plan9::FileSystem::IFileSystemUserOps *m_userOps;
                Plan9::Transport::ITransport          *m_transport;

        }; // Class IAuth
    } // Namespace Security
} // Namespace Plan9
#endif // __IAUTH_H
