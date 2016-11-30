#ifndef __ITRANSPORT_H_
#define __ITRANSPORT_H_

#include "P9Common.h"
#include "Fcall.h"

namespace Plan9
{
    namespace Transport
    {
        class ITransport
        {
            public:
                ITransport( int port ) 
                : m_Port(port)
                {};
                virtual ~ITransport( void ) {};

                virtual void getfcallnew(int fd, Plan9::Fcalls::Fcall *fc, uint have) = 0;
                virtual void getfcallold(int fd, Plan9::Fcalls::Fcall *fc, uint have) = 0;
                virtual void putfcallnew(int fd, Plan9::Fcalls::Fcall *tx) = 0;
                virtual void putfcallold(int fd, Plan9::Fcalls::Fcall *tx) = 0;
                virtual void getfcall(int *fd, Plan9::Fcalls::Fcall *fc) = 0;

                virtual void getremotehostname(char *name, int nname) = 0;

                virtual long readn(int f, void *av, long n) = 0;

                uchar*  rxbuf;
                uchar*  txbuf;
                void*   databuf;

            protected:
                int m_Port;

        }; // Class ITransport
    } // Namespace Transport
} // Namespace Plan9

#endif // __ITRANSPORT_H_
