#include <gmp.h> /*using gnu multiprecision library (gmp) for arbitrary length numbers*/

/*preprocesor directives*/
#ifdef _WIN32
#define CLEAR "cls"

#elif defined __gnu_linux__
#define CLEAR "clear"

#else
#define CLEAR "clear"

#endif


#define MAX_BUFFER_SIZE 1000 /*Maximum size of buffer for reading files*/
#define MAX_PATH_LEN 100 /*Maximum size of the file path*/

/*Macro to find the elapsed time*/
#define TIME(tfinal,tstart,sec) {sec=(double)(tfinal- tstart)/CLOCKS_PER_SEC;} 


typedef struct {
    
    mpz_t p; /*arbitrary length prime number p*/
    mpz_t q; /*arbitrary length prime number q*/
    mpz_t n; /*prime number multiplication*/
    mpz_t d; /*exponent d*/

}private_key;


typedef struct{

    mpz_t n; /*prime number multiplication*/
    mpz_t e; /*exponent e*/

}public_key;


/*function prototypes*/
void initialize_keys(public_key* publicKey, private_key*  privateKey);
void free_memory(public_key* publicKey, private_key*  privateKey);
int generate_keys(public_key* publicKey, private_key*  privateKey);
int get_bitlen(int* bitlen);
void encrypt(public_key* publicKey, mpz_t message, mpz_t encrypted);
void decrypt(private_key* privateKey, mpz_t message, mpz_t decrypted );
void show_menu();
void show_keys(public_key* pubkey, private_key* privkey, int base);
void exit_submenu();
void empty_buffer();
int mgetline(char s[], int lim);
int isnumber(char c);
int readfile(char* buffer, int maxbufflen);
void SaveFile(char* output, const char* filename);
