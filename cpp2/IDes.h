#ifndef __IDES_H_
#define __IDES_H_

#include "P9Common.h"

namespace Plan9
{
    namespace Security
    {
        class IDes
        {
            public:
                IDes( void ); // Actual constructor to fill in static arrays
                ~IDes( void ) {};
                /*
                 *	DES electronic codebook encryption of one block
                 */
                void block_cipher(char expanded_key[128], char text[8], int decrypting);
                void key_setup(char key[DESKEYLEN], char *ek);

            private:
                /*
                 *	Data Encryption Standard
                 *	D.P.Mitchell  83/06/08.
                 *
                 *	block_cipher(key, block, decrypting)
                 */

                long	ip_low(char [8]);
                long	ip_high(char [8]);
                void	fp(long, long, char[8]);
        }; // Class IDes

    } // Namespace Secutiry
} // Namespace Plan9
#endif // IDES_H_
