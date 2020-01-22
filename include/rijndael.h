#ifndef __RIJNDAEL_ALG_H
#define __RIJNDAEL_ALG_H

/* rijndael-alg-ref.h   v2.0   August '99
 * Reference ANSI C code
 * authors: Paulo Barreto
 *          Vincent Rijmen, K.U.Leuven
 */

#define MAXBC                (128/32)
#define MAXKC                (128/32)
#define MAXROUNDS            10
#define NUM_AES_BYTES        16
#define NUM_AES_ROWS         4
#define NUM_AES_COLUMNS      4

    typedef unsigned char uint8_t;
    typedef unsigned short word16;
    typedef unsigned long word32;


    int rijndaelKeySched(uint8_t k[4][MAXKC], int keyBits, int blockBits,
                         uint8_t rk[MAXROUNDS + 1][4][MAXBC]);

    int rijndaelEncrypt(uint8_t a[4][MAXBC], int keyBits, int blockBits,
                        uint8_t rk[MAXROUNDS + 1][4][MAXBC]);

    int rijndaelEncryptRound(uint8_t a[4][MAXBC], int keyBits, int blockBits,
                             uint8_t rk[MAXROUNDS + 1][4][MAXBC], int rounds);

    int rijndaelDecrypt(uint8_t a[4][MAXBC], int keyBits, int blockBits,
                        uint8_t rk[MAXROUNDS + 1][4][MAXBC]);

    int rijndaelDecryptRound(uint8_t a[4][MAXBC], int keyBits, int blockBits,
                             uint8_t rk[MAXROUNDS + 1][4][MAXBC], int rounds);

#endif /* __RIJNDAEL_ALG_H */
