//#########################################################################
//#
//# Copyright (C) 2021 José María Jaramillo Hoyos
//# 
//# This program is free software: you can redistribute it and/or modify
//# it under the terms of the GNU General Public License as published by
//# the Free Software Foundation, either version 3 of the License, or
//# (at your option) any later version.
//#
//# This program is distributed in the hope that it will be useful,
//# but WITHOUT ANY WARRANTY; without even the implied warranty of
//# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//# GNU General Public License for more details.
//#
//# You should have received a copy of the GNU General Public License
//# along with this program.  If not, see <https://www.gnu.org/licenses/>.
//#
//########################################################################*/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include "rsa.h"


/*Initialize public an private keys*/
void initialize_keys(public_key* publicKey, private_key*  privateKey){
    // Initialize mpz_t variables, and set their values to 0. This step
    // is necesary according the gmp library documentation
    mpz_inits(privateKey->p,privateKey->q,privateKey->n,privateKey->d,NULL);
    mpz_inits(publicKey->n,publicKey->e,NULL);
}

/*free the space in memory ocuped by the public and private keys*/
void free_memory(public_key* publicKey, private_key*  privateKey){
    
    mpz_clears(privateKey->p,privateKey->q,privateKey->n,privateKey->d,NULL);
    mpz_clears(publicKey->n,publicKey->e,NULL);

}


int get_bitlen(int* bitlen){

    int nitems;

    printf("Introduzca lo longitud en bits de los numeros primos p y q:\n");
    printf("-> ");

    nitems=scanf("%d",bitlen);
    empty_buffer();

    if(nitems){
        return 1;
    }

    else{
        printf("¡Please enter a valid number!\n");
        return 0;
    }

}


/*Function to generate the public and private keys*/
int generate_keys(public_key* publicKey, private_key*  privateKey){

    
    mpz_t  phi_n, subp, subq, gcd_e_phi, mul,mod;

    int bitLenght; /*Size in bits of prime numbers p and q*/

    if (!get_bitlen(&bitLenght)){
        return 0;
    }

    printf("Generating public and private keys.....\n");
    
    /*intitialize variables*/
    mpz_inits(phi_n,subp,subq,gcd_e_phi,mul,mod,NULL);

    /*Initialize keys*/
    initialize_keys(publicKey,privateKey);
     

    /* initialize the state object for the random generator functions*/
    gmp_randstate_t rstate;

    /*seed for the random generator function*/
    unsigned long seed;

    /*itialize state for a Mersenne Twister algorithm. 
    This algorithm is fast and has good randomness properties.*/
    gmp_randinit_mt(rstate);
    
    /*Set an initial seed value into rstate*/
    gmp_randseed_ui(rstate, seed);


    /*generate a random number p until p is a prime number, the function
    mpz_probab_prime_p() return whether p is prime or not based on the 
    Miller-Rabin probabilistic primality test which is based in the 
    riemann hypothesis */
    
    do{
       
       mpz_urandomb(privateKey->p,rstate,bitLenght);
    
    } while (!(mpz_probab_prime_p(privateKey->p, 25)));
     
  
    do{
        
        mpz_urandomb(privateKey->q,rstate,bitLenght);
    
    } while (!(mpz_probab_prime_p(privateKey->q, 25)));
    

    /* empty the memory location for the random generator state*/
    gmp_randclear(rstate);

    /*multiply p and and q and store the result in n*/
    mpz_mul(privateKey->n,privateKey->p,privateKey->q);
    mpz_set(publicKey->n,privateKey->n);

    mpz_sub_ui(subp,privateKey->p,1);
    mpz_sub_ui(subq,privateKey->q,1);
    mpz_mul(phi_n,subp,subq);


    /*Set initial value to publickey->e*/
    mpz_set_ui(publicKey->e,2);

    /*while publicKey->e < phi_n*/
    while (mpz_cmp(publicKey->e,phi_n)<0){
        
        /*greatest common divisor between e and phi_n*/
        mpz_gcd(gcd_e_phi,publicKey->e,phi_n);
        
        /*if gcd_e_phi is equal to 0*/
        if (mpz_cmp_si(gcd_e_phi,1)== 0){
            break;
        }
        else{
            /*increase publickey->e by 1*/
            mpz_add_ui(publicKey->e,publicKey->e,1);
        }
    }

    /*If the value of e was found then e < phi_n*/
    assert(mpz_cmp(publicKey->e,phi_n)<0);


    /*find the value of privateKey->d*/
    mpz_invert(privateKey->d, publicKey->e, phi_n);
    
    //  (e * d) MOD phi_n must be 1
    mpz_mul(mul, publicKey->e, privateKey->d);
    mpz_mod(mod, mul, phi_n);

    assert(mpz_cmp_ui(mod, 1) == 0);

    /*Garbage collection*/
    mpz_clears(phi_n,subp,subq,gcd_e_phi,mul,mod,NULL);

    return 1;
}


/*RSA encryption*/
void encrypt(public_key* publicKey, mpz_t message, mpz_t encrypted){

    mpz_powm(encrypted,message,publicKey->e,publicKey->n);
}

/*RSA decryption*/
void decrypt(private_key* privateKey, mpz_t message, mpz_t decrypted ){

    mpz_powm(decrypted,message,privateKey->d,privateKey->n);

}

void show_menu(){

    printf("*************************************************\n");
    printf("*                                               *\n");
    printf("*                RSA ALGORTIHM                  *\n");
    printf("*                                               *\n");
    printf("*                                               *\n");
    printf("*************************************************\n");
    printf("(1)\tGenerate keys\n");
    printf("(2)\tEncrypt message\n");
    printf("(3)\tDecrypt message\n");
    printf("(4)\tExit\n");
    printf("-> ");
}


void show_keys(public_key* pubkey, private_key* privkey, int base){

    printf("---------------Private Key------------------\n");
    printf("privkey.p is [%s]\n\n", mpz_get_str(NULL, base, privkey->p));
    printf("privkey.q is [%s]\n\n", mpz_get_str(NULL, base, privkey->q));
    printf("privkey.n is [%s]\n\n", mpz_get_str(NULL, base, privkey->n));
    printf("privkey.d is [%s]\n\n", mpz_get_str(NULL, base, privkey->d));
    printf("---------------Public Key-----------------\n");
    printf("pubkey.n is [%s]\n\n", mpz_get_str(NULL, base, pubkey->n));
    printf("pubkey.e is [%s]\n\n", mpz_get_str(NULL, base, pubkey->e));

}


void exit_submenu(){
    
    int command;
    printf("Press enter to return\n");
  do
  {
    command=getchar();
  } while (command != '\n'); 
  

}

void empty_buffer(){
    int command;
    while ((command=getchar()) != '\n'){
        ;
    }
}


/*Read a line from the console*/
int mgetline(char s[], int lim)
{
    int c,i;
    for ( i = 0; i < lim-1 && ((c=getchar()) != EOF) && c != '\n'; ++i)
    {
        s[i]=c;
    }
    s[i]='\0';
    return i; 
}


int isnumber(char c){
    if (c >= '0' && c <= '9'){
        return 1;
    }
    return 0;
}


int readfile(char* buffer, int maxbufflen){

    char PATH[MAX_PATH_LEN];
    int line_len,c,i;
    FILE* fp;

    printf("Introduce the File path:\n");
    printf("-> ");
    line_len = mgetline(PATH,MAX_PATH_LEN);

    fp=fopen(PATH,"r");

    /*if the function return a null pointer there was a problem reading the file*/
    if (fp == NULL) {
        printf("¡Please enter a valid path!\n");
        return 0;
    }

    for (i = 0; i < maxbufflen-1 && ((c=fgetc(fp))!=EOF); i++){

        if (isnumber(c)){
            buffer[i]=c;
        }
        
        else{
            printf("¡Please provide a valid input!\n");
            return 0;
        }
    }
    buffer[i]='\0'; /*null character*/

    fclose(fp);

    return 1;

}

void SaveFile(char* output, const char* filename){

    FILE* fp;

    fp=fopen(filename,"w");

    for (int i = 0; output[i] != '\0'; i++) {
        fputc(output[i],fp);
    }
    
    fclose(fp);

}


int main(int argc, char const *argv[]){

    public_key pubkey;
    private_key privkey;
    char buffer[MAX_BUFFER_SIZE];
    mpz_t encrypted;
    mpz_t decripted;
    mpz_t message;
    char* output;
    int command;
    int key_flag;

    clock_t start_time, end_time;
    double seconds;

    mpz_inits(encrypted,decripted,message,NULL);
    key_flag=0;
    
    do
    {
        system(CLEAR);
        show_menu();
        command = getchar();
    
        switch (command)
        {
            case '1':
                empty_buffer();
                system(CLEAR);
                
                start_time=clock();
                if(generate_keys(&pubkey,&privkey)){
                    end_time = clock();
                    show_keys(&pubkey,&privkey,10);
                    key_flag=1;
                    TIME(end_time,start_time,seconds);
                    printf("Key generation time:%lf seconds\n\n",seconds);
                }

                exit_submenu();

                break;

            case '2':
                empty_buffer();
                system(CLEAR);

                if (key_flag){
                    
                    if(readfile(buffer,MAX_BUFFER_SIZE)){
                    
                        // Interpret the array buffer as an int and save it into message variable
                        mpz_set_str(message,buffer,10);
                        printf("Encrypting message...\n");
                        start_time=clock();
                        encrypt(&pubkey,message,encrypted);
                        end_time = clock();
                        output= (char*) malloc(mpz_sizeinbase(encrypted,10) + 1);
                        mpz_get_str(output,10,encrypted);
                        printf("Generating output Encrypted.txt...\n\n");
                        SaveFile(output,"Encrypted.txt");
                        free(output); /*free dinamic memory*/
                        TIME(end_time,start_time,seconds);
                        printf("Encryption time:%lf seconds\n\n",seconds);

                    }

                }
                else{
                    printf("WARNING:¡No public and private key has been generated!\n\n");
                }
                
                exit_submenu();
                break;

            
            case '3':

                empty_buffer();
                system(CLEAR);

                if (key_flag){

                    if(readfile(buffer,MAX_BUFFER_SIZE)){

                        mpz_set_str(message,buffer,10);
                        printf("Decrypting message...\n");
                        start_time=clock();
                        decrypt(&privkey,message,decripted);
                        end_time=clock();
                        output= (char*) malloc(mpz_sizeinbase(decripted,10) + 1);
                        mpz_get_str(output,10,decripted);
                        printf("Generating output Decrypted.txt...\n\n");
                        SaveFile(output,"Decrypted.txt");
                        free(output); /*free dinamic memory*/
                        TIME(end_time,start_time,seconds);
                        printf("Decryption time:%lf seconds\n\n",seconds);

                    }
                }

                else{
                    printf("WARNING:¡No public and private key has been generated!\n\n");
                }

                exit_submenu();

                break;

            default:
                empty_buffer();
                system(CLEAR);
                break;
        }

    } while (command != '4');


    /*Garbage collection*/
    mpz_clears(encrypted,decripted,message,NULL);

    if (key_flag) {
        free_memory(&pubkey,&privkey);
    }
    
    
    return 0;
}
