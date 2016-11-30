#ifndef __P9CONVERSION_H_
#define __P9CONVERSION_H_

#include	"P9Common.h"

#define lock(x)
#define unlock(x)

namespace Plan9
{
    namespace Conversion
    {
        static Rune null[] = { L'<', L'n', L'u', L'l', L'l', L'>', L'\0' };

        enum
        {
                UTFmax          = 3,            /* maximum bytes per rune */
                Runesync        = 0x80,         /* cannot represent part of a UTF sequence (<) */
                Runeself        = 0x80,         /* rune and UTF sequences are the same (<) */
                Runeerror       = 0x80          /* decoding error in UTF */
        };

        enum
        {
	        IDIGIT	= 40,
	        MAXCONV	= 40,
	        FDIGIT	= 30,
	        FDEFLT	= 6,
	        NONE	= -1000,
	        MAXFMT	= 512,
        
	        FPLUS	= 1<<0,
	        FMINUS	= 1<<1,
	        FSHARP	= 1<<2,
	        FLONG	= 1<<3,
	        FUNSIGN	= 1<<5,
	        FVLONG	= 1<<6,
	        FPOINTER= 1<<7
        };

        enum
        {
                Bit1    = 7,
                Bitx    = 6,
                Bit2    = 5,
                Bit3    = 4,
                Bit4    = 3,
        
                T1      = ((1<<(Bit1+1))-1) ^ 0xFF,     /* 0000 0000 */
                Tx      = ((1<<(Bitx+1))-1) ^ 0xFF,     /* 1000 0000 */
                T2      = ((1<<(Bit2+1))-1) ^ 0xFF,     /* 1100 0000 */
                T3      = ((1<<(Bit3+1))-1) ^ 0xFF,     /* 1110 0000 */
                T4      = ((1<<(Bit4+1))-1) ^ 0xFF,     /* 1111 0000 */
        
                Rune1   = (1<<(Bit1+0*Bitx))-1,         /* 0000 0000 0111 1111 */
                Rune2   = (1<<(Bit2+1*Bitx))-1,         /* 0000 0111 1111 1111 */
                Rune3   = (1<<(Bit3+2*Bitx))-1,         /* 1111 1111 1111 1111 */
        
                Maskx   = (1<<Bitx)-1,                  /* 0011 1111 */
                Testx   = Maskx ^ 0xFF,                 /* 1100 0000 */
        
                Bad     = Runeerror
        };
        
        extern int	printcol;

        typedef struct  Fconv
        {
                char*   out;            /* pointer to next output */
                char*   eout;           /* pointer to end */
                int     f1;
                int     f2;
                int     f3;
                int     chr;
        } Fconv;
        
        static struct
        {
        /*	Lock;	*/
	        int	convcount;
	        char	index[MAXFMT];
	        int	(*conv[MAXCONV])(va_list*, Fconv*);
        } fmtalloc;
        
        int	noconv(va_list*, Fconv*);
        int	flags(va_list*, Fconv*);
        
        int	cconv(va_list*, Fconv*);
        int	sconv(va_list*, Fconv*);
        int	percent(va_list*, Fconv*);
        int	column(va_list*, Fconv*);

        void    initfmt(void);
        int     fmtinstall(int c, int (*f)(va_list*, Fconv*));
        void    pchar(Rune c, Fconv *fp);
        char   *doprint(char *s, char *es, const char *fmt, va_list *argp);
        int     numbconv(va_list *arg, Fconv *fp);
        void    Strconv(Rune *s, Fconv *fp);
        void    strconv(char *s, Fconv *fp);
        int     noconv(va_list *va, Fconv *fp);
        int     cconv(va_list *arg, Fconv *fp);
        int     sconv(va_list *arg, Fconv *fp);
        int     percent(va_list *va, Fconv *fp);
        int     column(va_list *arg, Fconv *fp);
        int     flags(va_list *va, Fconv *fp);

        int     runetochar(char*, Rune*);
        int     chartorune(Rune*, const char*);
        int     runelen(long);
        int     utflen(char *s);


        /*
         * This code is superseded by the more accurate (but more complex)
         * algorithm in fltconv.c and dtoa.c.  Uncomment this routine to avoid
         * using the more complex code.
         *
         */

    } // Namespace Conversion
} // Namespace Plan9

#endif // __P9CONVERSION_H
