#include "P9Common.h"
#include "ITransport.h"

namespace Plan9
{
    namespace Transport
    {
        class StdinTransport : public ITransport
        {
            public:
                StdinTransport( int input, int output ) : ITransport(0), m_infd(input), m_outfd(output)
                {};
                ~StdinTransport( void ) {};

                void getfcallnew(int fd, Plan9::Fcalls::Fcall *fc, int have);
                void getfcallold(int fd, Plan9::Fcalls::Fcall *fc, int have);
                void putfcallnew(int wfd, Plan9::Fcalls::Fcall *tx);
                void putfcallold(int wfd, Plan9::Fcalls::Fcall *tx);
                void getfcall(Plan9::Fcalls::Fcall *fc);

                void getremotehostname(char *name, int nname);

                long readn(int f, void *av, long n);

            private:
                int         m_infd;
                int         m_outfd;

        }; // Class ITransport
    } // Namespace Transport
} // Namespace Plan9
