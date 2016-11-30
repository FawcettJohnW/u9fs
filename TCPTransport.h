#include "P9Common.h"
#include "ITransport.h"
#include "Fcall.h"
#include <semaphore.h>
#include <pthread.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include <queue>


namespace Plan9
{
    namespace Transport
    {
        class TCPTransport : public ITransport
        {
            public:
                TCPTransport( int Port );
                ~TCPTransport( void );

                void getfcallnew(int fd, Plan9::Fcalls::Fcall *fc, int have);
                void getfcallold(int fd, Plan9::Fcalls::Fcall *fc, int have);
                void putfcallnew(int fd, Plan9::Fcalls::Fcall *tx);
                void putfcallold(int fd, Plan9::Fcalls::Fcall *tx);
                void getfcall(int *fd, Plan9::Fcalls::Fcall *fc);

                void getremotehostname(char *name, int nname);

                long readn(int f, void *av, long n);

                void AddNewListener(int newsock)
                {
                    pthread_mutex_lock(&m_queueLock);
                    m_socketList.push_back(newsock);
                    pthread_mutex_unlock(&m_queueLock);
                }

                void *TCPListener( void *args );
                void *TCPAcceptor( void *args );

            private:
                int                 m_serverSock;

                typedef struct _fcallMessage
                {
                    int sock; // the socket it came in on
                    Plan9::Fcalls::Fcall* fc; // The message
                } fcallMessage;

                pthread_t           m_AcceptorThread;;
                pthread_t           m_ListenerThread;

                sem_t               m_semaphore;
                pthread_mutex_t     m_queueLock;

                std::queue<fcallMessage *> m_messageQueue;
                std::vector<int>    m_socketList;

                bool                m_Running;

                int                 m_currentSock;

                void                tcpSysFatal(int fd, const char*, ...);
        }; // Class ITransport
    } // Namespace Transport
} // Namespace Plan9
