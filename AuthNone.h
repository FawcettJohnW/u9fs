#ifndef __AUTHNONE_H_
#define __AUTHNONE_H_
#include "P9Common.h"
#include "IAuth.h"

//
//  ***** This is a header file implementation only.  There is no cpp file for this class
//
namespace Plan9
{
    namespace Security
    {
        class AuthNone : public IAuth
        {
            public:
                AuthNone(std::string name, Plan9::P9UserMgmt::P9Users* users, Plan9::FileSystem::IFileSystemUserOps* userOps, Plan9::Transport::ITransport* transport)
                      : IAuth(name, users, userOps, transport)
                { }
                virtual ~AuthNone( void ) {};

                const char * MakeAuthCall(Fcall *rx, Fcall *tx)
                {
                        static char noauth[]="u9fs authnone: no authentication required";
                  USED(rx);
                  USED(tx);
                  return noauth;
                };

                const char * MakeAttachCall(Fcall *rx, Fcall *tx)
                {
                  USED(rx);
                  USED(tx);
                  return NULL;
                };
               // These methods not implemented...
               void         MakeInitCall(void) {};
               const char * MakeReadCall(Fcall *rx, Fcall *tx) {return errStr;};
               const char * MakeWriteCall(Fcall *rx, Fcall *tx) {return errStr;};
               const char * MakeClunkCall(Fcall *rx, Fcall *tx) {return errStr;};
        }; // class AuthNone
    } // Namespace Security
} // Namespace Plan9
#endif // __AUTHNONE_H_
