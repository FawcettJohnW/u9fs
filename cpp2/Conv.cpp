#include	"Conv.h"

using namespace Plan9;
using namespace Plan9::Common;
using namespace Plan9::Conversion;

int Plan9::Conversion::printcol;

void
Plan9::Conversion::initfmt(void)
{
	int cc;

	lock(&fmtalloc);
	if(fmtalloc.convcount <= 0) {
		cc = 0;
		fmtalloc.conv[cc] = noconv;
		cc++;

		fmtalloc.conv[cc] = flags;
		fmtalloc.index['+'] = cc;
		fmtalloc.index['-'] = cc;
		fmtalloc.index['#'] = cc;
		fmtalloc.index['l'] = cc;
		fmtalloc.index['u'] = cc;
		cc++;

		fmtalloc.conv[cc] = numbconv;
		fmtalloc.index['d'] = cc;
		fmtalloc.index['o'] = cc;
		fmtalloc.index['x'] = cc;
		fmtalloc.index['X'] = cc;
		fmtalloc.index['p'] = cc;
		cc++;


		fmtalloc.conv[cc] = cconv;
		fmtalloc.index['c'] = cc;
		fmtalloc.index['C'] = cc;
		cc++;

		fmtalloc.conv[cc] = sconv;
		fmtalloc.index['s'] = cc;
		fmtalloc.index['S'] = cc;
		cc++;

		fmtalloc.conv[cc] = percent;
		fmtalloc.index['%'] = cc;
		cc++;

		fmtalloc.conv[cc] = column;
		fmtalloc.index['|'] = cc;
		cc++;

		fmtalloc.convcount = cc;
	}
	unlock(&fmtalloc);
}

int
Plan9::Conversion::fmtinstall(int c, int (*f)(va_list*, Fconv*))
{

	if(fmtalloc.convcount <= 0)
		initfmt();

	lock(&fmtalloc);
	if(c < 0 || c >= MAXFMT) {
		unlock(&fmtalloc);
		return -1;
	}
	if(fmtalloc.convcount >= MAXCONV) {
		unlock(&fmtalloc);
		return -1;
	}
	fmtalloc.conv[fmtalloc.convcount] = f;
	fmtalloc.index[c] = fmtalloc.convcount;
	fmtalloc.convcount++;

	unlock(&fmtalloc);
	return 0;
}

void
Plan9::Conversion::pchar(Rune c, Fconv *fp)
{
	int n;

	n = fp->eout - fp->out;
	if(n > 0) {
		if(c < Runeself) {
			*fp->out++ = c;
			return;
		}
		if(n >= UTFmax || n >= runelen(c)) {
			n = runetochar(fp->out, &c);
			fp->out += n;
			return;
		}
		fp->eout = fp->out;
	}
}

char*
Plan9::Conversion::doprint(char *s, char *es, const char *fmt, va_list *argp)
{
	int n, c;
	Rune rune;
	Fconv local;

	if(fmtalloc.convcount <= 0)
		initfmt();

	if(s >= es)
		return s;
	local.out = s;
	local.eout = es-1;

loop:
	c = *fmt & 0xff;
	if(c >= Runeself) {
		n = chartorune(&rune, fmt);
		fmt += n;
		c = rune;
	} else
		fmt++;
	switch(c) {
	case 0:
		*local.out = 0;
		return local.out;
	
	default:
		printcol++;
		goto common;

	case '\n':
		printcol = 0;
		goto common;

	case '\t':
		printcol = (printcol+8) & ~7;
		goto common;

	common:
		pchar(c, &local);
		goto loop;

	case '%':
		break;
	}
	local.f1 = NONE;
	local.f2 = NONE;
	local.f3 = 0;

	/*
	 * read one of the following
	 *	1. number, => f1, f2 in order.
	 *	2. '*' same as number (from args)
	 *	3. '.' ignored (separates numbers)
	 *	4. flag => f3
	 *	5. verb and terminate
	 */
l0:
	c = *fmt & 0xff;
	if(c >= Runeself) {
		n = chartorune(&rune, fmt);
		fmt += n;
		c = rune;
	} else
		fmt++;

l1:
	if(c == 0) {
		fmt--;
		goto loop;
	}
	if(c == '.') {
		if(local.f1 == NONE)
			local.f1 = 0;
		local.f2 = 0;
		goto l0;
	}
	if((c >= '1' && c <= '9') ||
	   (c == '0' && local.f1 != NONE)) {	/* '0' is a digit for f2 */
		n = 0;
		while(c >= '0' && c <= '9') {
			n = n*10 + c-'0';
			c = *fmt++;
		}
		if(local.f1 == NONE)
			local.f1 = n;
		else
			local.f2 = n;
		goto l1;
	}
	if(c == '*') {
		n = va_arg(*argp, int);
		if(local.f1 == NONE)
			local.f1 = n;
		else
			local.f2 = n;
		goto l0;
	}
	n = 0;
	if(c >= 0 && c < MAXFMT)
		n = fmtalloc.index[c];
	local.chr = c;
	n = (*fmtalloc.conv[n])(argp, &local);
	if(n < 0) {
		local.f3 |= -n;
		goto l0;
	}
	goto loop;
}

int
Plan9::Conversion::numbconv(va_list *arg, Fconv *fp)
{
	char s[IDIGIT];
	int i, f, n, b, ucase;
	long v;
	vlong vl;

	SET(v);
	SET(vl);

	ucase = 0;
	b = fp->chr;
	switch(fp->chr) {
	case 'u':
		fp->f3 |= FUNSIGN;
	case 'd':
		b = 10;
		break;

	case 'b':
		b = 2;
		break;

	case 'o':
		b = 8;
		break;

	case 'X':
		ucase = 1;
	case 'x':
		b = 16;
		break;
	case 'p':
		fp->f3 |= FPOINTER|FUNSIGN;
		b = 16;
		break;
	}

	f = 0;
	switch(fp->f3 & (FVLONG|FLONG|FUNSIGN|FPOINTER)) {
	case FVLONG|FLONG:
		vl = va_arg(*arg, vlong);
		break;

	case FUNSIGN|FVLONG|FLONG:
		vl = va_arg(*arg, uvlong);
		break;

	case FUNSIGN|FPOINTER:
		v = (ulong)va_arg(*arg, void*);
		break;

	case FLONG:
		v = va_arg(*arg, long);
		break;

	case FUNSIGN|FLONG:
		v = va_arg(*arg, ulong);
		break;

	default:
		v = va_arg(*arg, int);
		break;

	case FUNSIGN:
		v = va_arg(*arg, unsigned);
		break;
	}
	if(fp->f3 & FVLONG) {
		if(!(fp->f3 & FUNSIGN) && vl < 0) {
			vl = -vl;
			f = 1;
		}
	} else {
		if(!(fp->f3 & FUNSIGN) && v < 0) {
			v = -v;
			f = 1;
		}
	}
	s[IDIGIT-1] = 0;
	for(i = IDIGIT-2;; i--) {
		if(fp->f3 & FVLONG)
			n = (uvlong)vl % b;
		else
			n = (ulong)v % b;
		n += '0';
		if(n > '9') {
			n += 'a' - ('9'+1);
			if(ucase)
				n += 'A'-'a';
		}
		s[i] = n;
		if(i < 2)
			break;
		if(fp->f3 & FVLONG)
			vl = (uvlong)vl / b;
		else
			v = (ulong)v / b;
		if(fp->f2 != NONE && i >= IDIGIT-fp->f2)
			continue;
		if(fp->f3 & FVLONG) {
			if(vl <= 0)
				break;
			continue;
		}
		if(v <= 0)
			break;
	}

	if(fp->f3 & FSHARP) {
		if(b == 8 && s[i] != '0')
			s[--i] = '0';
		if(b == 16) {
			if(ucase)
				s[--i] = 'X';
			else
				s[--i] = 'x';
			s[--i] = '0';
		}
	}
	if(f)
		s[--i] = '-';
	else if(fp->f3 & FPLUS)
		s[--i] = '+';

	fp->f2 = NONE;
	strconv(s+i, fp);
	return 0;
}

void
Plan9::Conversion::Strconv(Rune *s, Fconv *fp)
{
	int n, c;

	if(fp->f3 & FMINUS)
		fp->f1 = -fp->f1;
	n = 0;
	if(fp->f1 != NONE && fp->f1 >= 0) {
		for(; s[n]; n++)
			;
		while(n < fp->f1) {
			pchar(' ', fp);
			printcol++;
			n++;
		}
	}
	for(;;) {
		c = *s++;
		if(c == 0)
			break;
		n++;
		if(fp->f2 == NONE || fp->f2 > 0) {
			pchar(c, fp);
			if(fp->f2 != NONE)
				fp->f2--;
			switch(c) {
			default:
				printcol++;
				break;
			case '\n':
				printcol = 0;
				break;
			case '\t':
				printcol = (printcol+8) & ~7;
				break;
			}
		}
	}
	if(fp->f1 != NONE && fp->f1 < 0) {
		fp->f1 = -fp->f1;
		while(n < fp->f1) {
			pchar(' ', fp);
			printcol++;
			n++;
		}
	}
}

void
Plan9::Conversion::strconv(char *s, Fconv *fp)
{
	int n, c, i;
	Rune rune;

	if(fp->f3 & FMINUS)
		fp->f1 = -fp->f1;
	n = 0;
	if(fp->f1 != NONE && fp->f1 >= 0) {
		n = utflen(s);
		while(n < fp->f1) {
			pchar(' ', fp);
			printcol++;
			n++;
		}
	}
	for(;;) {
		c = *s & 0xff;
		if(c >= Runeself) {
			i = chartorune(&rune, s);
			s += i;
			c = rune;
		} else
			s++;
		if(c == 0)
			break;
		n++;
		if(fp->f2 == NONE || fp->f2 > 0) {
			pchar(c, fp);
			if(fp->f2 != NONE)
				fp->f2--;
			switch(c) {
			default:
				printcol++;
				break;
			case '\n':
				printcol = 0;
				break;
			case '\t':
				printcol = (printcol+8) & ~7;
				break;
			}
		}
	}
	if(fp->f1 != NONE && fp->f1 < 0) {
		fp->f1 = -fp->f1;
		while(n < fp->f1) {
			pchar(' ', fp);
			printcol++;
			n++;
		}
	}
}

int
Plan9::Conversion::noconv(va_list *va, Fconv *fp)
{
	char s[10];

	USED(va);
	s[0] = '*';
	s[1] = fp->chr;
	s[2] = '*';
	s[3] = 0;
	fp->f1 = 0;
	fp->f2 = NONE;
	fp->f3 = 0;
	strconv(s, fp);
	return 0;
}

int
Plan9::Conversion::cconv(va_list *arg, Fconv *fp)
{
	char s[10];
	Rune rune;

	rune = va_arg(*arg, int);
	if(fp->chr == 'c')
		rune &= 0xff;
	s[runetochar(s, &rune)] = 0;

	fp->f2 = NONE;
	strconv(s, fp);
	return 0;
}

static char nullMsg[] = "<null>";

int
Plan9::Conversion::sconv(va_list *arg, Fconv *fp)
{
	char *s;
	Rune *r;

	if(fp->chr == 's') {
		s = va_arg(*arg, char*);
		if(s == 0)
			s = nullMsg;
		strconv(s, fp);
	} else {
		r = va_arg(*arg, Rune*);
		if(r == 0)
			r = null;
		Strconv(r, fp);
	}
	return 0;
}

int
Plan9::Conversion::percent(va_list *va, Fconv *fp)
{
	USED(va);

	pchar('%', fp);
	printcol++;
	return 0;
}

int
Plan9::Conversion::column(va_list *arg, Fconv *fp)
{
	int col, pc;

	col = va_arg(*arg, int);
	while(printcol < col) {
		pc = (printcol+8) & ~7;
		if(pc <= col) {
			pchar('\t', fp);
			printcol = pc;
		} else {
			pchar(' ', fp);
			printcol++;
		}
	}
	return 0;
}

int
Plan9::Conversion::flags(va_list *va, Fconv *fp)
{
	int f;

	USED(va);
	f = 0;
	switch(fp->chr) {
	case '+':
		f = FPLUS;
		break;

	case '-':
		f = FMINUS;
		break;

	case '#':
		f = FSHARP;
		break;

	case 'l':
		f = FLONG;
		if(fp->f3 & FLONG)
			f = FVLONG;
		break;

	case 'u':
		f = FUNSIGN;
		break;
	}
	return -f;
}

int
Plan9::Conversion::chartorune(Rune *rune, const char *str)
{
	int c, c1, c2;
	long l;

	/*
	 * one character sequence
	 *	00000-0007F => T1
	 */
	c = *(uchar*)str;
	if(c < Tx) {
		*rune = c;
		return 1;
	}

	/*
	 * two character sequence
	 *	0080-07FF => T2 Tx
	 */
	c1 = *(uchar*)(str+1) ^ Tx;
	if(c1 & Testx)
		goto bad;
	if(c < T3) {
		if(c < T2)
			goto bad;
		l = ((c << Bitx) | c1) & Rune2;
		if(l <= Rune1)
			goto bad;
		*rune = l;
		return 2;
	}

	/*
	 * three character sequence
	 *	0800-FFFF => T3 Tx Tx
	 */
	c2 = *(uchar*)(str+2) ^ Tx;
	if(c2 & Testx)
		goto bad;
	if(c < T4) {
		l = ((((c << Bitx) | c1) << Bitx) | c2) & Rune3;
		if(l <= Rune2)
			goto bad;
		*rune = l;
		return 3;
	}

	/*
	 * bad decoding
	 */
bad:
	*rune = Bad;
	return 1;
}

int
Plan9::Conversion::runetochar(char *str, Rune *rune)
{
	long c;

	/*
	 * one character sequence
	 *	00000-0007F => 00-7F
	 */
	c = *rune;
	if(c <= Rune1) {
		str[0] = c;
		return 1;
	}

	/*
	 * two character sequence
	 *	0080-07FF => T2 Tx
	 */
	if(c <= Rune2) {
		str[0] = T2 | (c >> 1*Bitx);
		str[1] = Tx | (c & Maskx);
		return 2;
	}

	/*
	 * three character sequence
	 *	0800-FFFF => T3 Tx Tx
	 */
	str[0] = T3 |  (c >> 2*Bitx);
	str[1] = Tx | ((c >> 1*Bitx) & Maskx);
	str[2] = Tx |  (c & Maskx);
	return 3;
}

int
Plan9::Conversion::runelen(long c)
{
	Rune rune;
	char str[10];

	rune = c;
	return runetochar(str, &rune);
}

int
Plan9::Conversion::utflen(char *s)
{
	int c;
	long n;
	Rune rune;

	n = 0;
	for(;;) {
		c = *(uchar*)s;
		if(c < Runeself) {
			if(c == 0)
				return n;
			s++;
		} else
			s += chartorune(&rune, s);
		n++;
	}
	return 0;
}
