#ifndef __P9USER_H_
#define __P9USER_H_
#include "P9Common.h"
#include "Logging.h"
#include <pwd.h>
#include <sys/types.h>
#include <grp.h>

namespace Plan9
{    
    namespace P9UserMgmt
    {
        class P9User
        {
            public:
                P9User( void )
                : id(0), defaultgid(0), name(NULL), mem(NULL), nmem(0), next(NULL)
                {};
                virtual ~P9User( void ) {};

                int id;
                gid_t defaultgid;
                char *name;
                char **mem;     /* group members */
                int nmem;
                P9User *next;
        };

        class P9Users
        {
            public:
                P9Users( void )
                : utab(), gtab()
                {};
                ~P9Users( void ) {};

            public:
                P9User* adduser(const struct passwd *p);
                int useringroup(P9User *u, P9User *g);
                P9User* addgroup(struct group *g);
                P9User* uname2user(const char *name);
                P9User* uid2user(int id);
                P9User* gname2user(char *name);
                P9User* gid2user(int id);

                inline P9User *GetUtabEntry(int index)
                {
                    return utab[index];
                }

                inline void SetUtabEntry(int index, P9User* newUserPtr)
                {
                    utab[index] = newUserPtr;
                }

                inline P9User *GetGtabEntry(int index)
                {
                    return gtab[index];
                }

                inline void SetGtabEntry(int index, P9User* newUserPtr)
                {
                    gtab[index] = newUserPtr;
                }

                inline int GetNumUtab( void )
                {
                    return nelem(utab);
                }

                inline int GetNumGtab( void )
                {
                    return nelem(gtab);
                }

            private:
                /*
                 * we keep a table by numeric id.  by name lookups happen infrequently
                 * while by-number lookups happen once for every directory entry read
                 * and every stat request.
                 */
                P9User *utab[64];
                P9User *gtab[64];

        };  // Class Users

       static P9User *none = NULL;
    } // namespace Users
} // namespace Plan9
#endif // __P9USER_H_
