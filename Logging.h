#ifndef __P9LOGGING_H_
#define __P9LOGGING_H_

#include "P9Common.h"

namespace Plan9
{
    namespace Common
    {
        class Logging
        {
            public:
                // static char*   doprint(char*, char*, char*, va_list *argp);
                static int     print(const char*, ...);
                static char*   seprint(char*, char*, const char*, ...);
                static char*   smprint(const char*, ...);
                static int     snprint(char*, int, const char*, ...);
                static int     sprint(char*, const char*, ...);
                static int     fprint(int, const char*, ...);
                static void    sysfatal(const char*, ...);
                static int     tokenize(char*, char**, int);
                static int     getfields(char*, char**, int, int, const char*);
                static char*   strecpy(char*, char*, char*);

            private:
                static int     runetochar(char*, Rune*);
                static int     chartorune(Rune*, char*);
                static int     runelen(long);
                static int     utflen(char*);
                static const char* utfrune(const char*, long);
        }; // Class p9Logging
    } // namespace Logging
} // namespace Plan9
            
#endif // __P9LOGGING_H_
