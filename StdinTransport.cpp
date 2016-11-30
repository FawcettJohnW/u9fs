#include "StdinTransport.h"
#include "Logging.h"

#include <sys/types.h>
#include <sys/socket.h> /* various networking crud */
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

using namespace Plan9;
using namespace Plan9::Common;
using namespace Plan9::Fcalls;

void
Plan9::Transport::StdinTransport::getfcallnew(int fd, Fcall *fc, int have)
{
Logging::fprint(2, "getfcallnew entry\n");
	int len;

	if(have > BIT32SZ)
		Logging::sysfatal("cannot happen");

Logging::fprint(2, "have (%d) is < BIT32SZ (%d)\n", have, BIT32SZ);
	if(have < BIT32SZ && readn(fd, rxbuf+have, BIT32SZ-have) != BIT32SZ-have)
		Logging::sysfatal("couldn't read message");

Logging::fprint(2, "Read in message\n");
	len = GBIT32(rxbuf);
Logging::fprint(2, "Got length.  Is is %d\n", len);
	if(len <= BIT32SZ)
		Logging::sysfatal("bogus message");

Logging::fprint(2, "Adjusting length\n");
	len -= BIT32SZ;
Logging::fprint(2, "New length is %d\n", len);
	if(readn(fd, rxbuf+BIT32SZ, len) != len)
		Logging::sysfatal("short message");

Logging::fprint(2, "Converting...\n");
	if(convM2S(rxbuf, len+BIT32SZ, fc) != len+BIT32SZ)
		Logging::sysfatal("getfcallnew:  badly sized message type %d", rxbuf[0]);
Logging::fprint(2, "Conversion completed...\n");
}

void
Plan9::Transport::StdinTransport::getfcallold(int fd, Fcall *fc, int have)
{
Logging::fprint(2, "getfcallold entry\n");
	int len, n;

	if(have > 3)
		Logging::sysfatal("cannot happen");

	if(have < 3 && readn(fd, rxbuf, 3-have) != 3-have)
		Logging::sysfatal("couldn't read message");

	len = oldhdrsize(rxbuf[0]);
	if(len < 3)
		Logging::sysfatal("bad message %d", rxbuf[0]);
	if(len > 3 && readn(fd, rxbuf+3, len-3) != len-3)
		Logging::sysfatal("couldn't read message");

	n = iosize(rxbuf);
	if(readn(fd, rxbuf+len, n) != n)
		Logging::sysfatal("couldn't read message");
	len += n;

	if(convM2Sold(rxbuf, len, fc) != len)
		Logging::sysfatal("convM2Sold: badly sized message type %d", rxbuf[0]);
}

void
Plan9::Transport::StdinTransport::putfcallnew(Fcall *tx)
{
Logging::fprint(2, "putfcallnew entry\n");
	uint n;

	if((n = convS2M(tx, txbuf, msize)) == 0)
		Logging::sysfatal("couldn't format message type %d", tx->type);
	if(write(m_outfd, txbuf, n) != n)
		Logging::sysfatal("couldn't send message");
}

void
Plan9::Transport::StdinTransport::putfcallold(Fcall *tx)
{
	uint n;
Logging::fprint(2, "putfcallold entry\n");

	if((n = convS2Mold(tx, txbuf, msize)) == 0)
		Logging::sysfatal("couldn't format message type %d", tx->type);
	if(write(m_outfd, txbuf, n) != n)
		Logging::sysfatal("couldn't send message");
}

void
Plan9::Transport::StdinTransport::getfcall(Fcall *fc)
{
Logging::fprint(2, "getfcall entry\n");
	if(old9p == 1){
		getfcallold(m_infd, fc, 0);
		return;
	}
	if(old9p == 0){
		getfcallnew(m_infd, fc, 0);
		return;
	}

	/* auto-detect */
	if(readn(m_infd, rxbuf, 3) != 3)
		Logging::sysfatal("couldn't read message");

	/* is it an old (9P1) message? */
	if(50 <= rxbuf[0] && rxbuf[0] <= 87 && (rxbuf[0]&1)==0 && GBIT16(rxbuf+1) == 0xFFFF){
		old9p = 1;
		getfcallold(m_infd, fc, 3);
		return;
	}

	getfcallnew(m_infd, fc, 3);
	old9p = 0;
}

long
Plan9::Transport::StdinTransport::readn(int f, void *av, long n)
{
	char *a;
	long m, t;

	a = reinterpret_cast<char *>(av);
	t = 0;
	while(t < n){
		m = read(f, a+t, n-t);
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
Plan9::Transport::StdinTransport::getremotehostname(char *name, int nname)
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

