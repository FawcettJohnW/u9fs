#ifndef __AUTHRHOSTS_H_
#define __AUTHRHOSTS_H_

#include "P9Common.h"
#include "IAuth.h"
#include "Logging.h"

//
//  ***** This is a header file implementation only.  There is no cpp file for this class
//
namespace Plan9
{
    namespace Security
    {
        class RHostsAuth : public IAuth
        {
            friend class IAuth;

            public:
                RHostsAuth( std::string name, Plan9::P9UserMgmt::P9Users* users, Plan9::FileSystem::IFileSystemUserOps* userOps, Plan9::Transport::ITransport* transport ) 
                    : IAuth(name, users, userOps, transport)
                { }
                virtual ~RHostsAuth( void ) {};

                /*
                * return whether the user is authenticated.
                * uses berkeley-style rhosts ``authentication''.
                * this is only a good idea behind a firewall,
                * where you trust your network, and even then
                * not such a great idea.  it's grandfathered.
                */

               char* MakeAuthCall(Fcall *rx, Fcall *tx)
               {
                   static char noauth[]="u9fs rhostsauth: no authentication required";

                   USED(rx);
                   USED(tx);
               
                   return noauth;
               }
               
               char* MakeAttachCall(Fcall *rx, Fcall *tx)
               {
                   static char authfailed[]="u9fs: rhosts authentication failed";

                   USED(tx);
               
                   if(ruserok(remotehostname, 0, rx->uname, rx->uname) < 0){
                       Logging::fprint(2, "ruserok(%s, %s) not okay\n", remotehostname, rx->uname);
                   return authfailed;
                   }
                   return 0;
               }

               // These methods not implemented...
               void     MakeInitCall(void) {};
               char *   MakeReadCall(Fcall *rx, Fcall *tx) {return errStr;};
               char *   MakeWriteCall(Fcall *rx, Fcall *tx) {return errStr;};
               char *   MakeClunkCall(Fcall *rx, Fcall *tx) {return errStr;};
        }; // class RHostsAuth
    } // Namespace Security
} // Namespace Plan9
#endif // __AUTHRHOSTS_H_
