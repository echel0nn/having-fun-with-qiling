#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h> //Only needed for strlen().
#define ADD 0x42
#define SUB 0x26
#define XOR 0x40
#define FLAG_SIZE 36  // change if the flag size is changed
#define CODE_SIZE 108 // change if you have new echelon code

/* A BASE-64 ENCODER AND DECODER USING OPENSSL */
char *base64encode (const void *b64_encode_this, int encode_this_many_bytes){
    BIO *b64_bio, *mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
    BUF_MEM *mem_bio_mem_ptr;    //Pointer to a "memory BIO" structure holding our base64 data.
    b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
    mem_bio = BIO_new(BIO_s_mem());                           //Initialize our memory sink BIO.
    BIO_push(b64_bio, mem_bio);            //Link the BIOs by creating a filter-sink BIO chain.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);  //No newlines every 64 characters or less.
    BIO_write(b64_bio, b64_encode_this, encode_this_many_bytes); //Records base64 encoded data.
    BIO_flush(b64_bio);   //Flush data.  Necessary for b64 encoding, because of pad characters.
    BIO_get_mem_ptr(mem_bio, &mem_bio_mem_ptr);  //Store address of mem_bio's memory structure.
    BIO_set_close(mem_bio, BIO_NOCLOSE);   //Permit access to mem_ptr after BIOs are destroyed.
    BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
    BUF_MEM_grow(mem_bio_mem_ptr, (*mem_bio_mem_ptr).length + 1);   //Makes space for end null.
    (*mem_bio_mem_ptr).data[(*mem_bio_mem_ptr).length] = '\0';  //Adds null-terminator to tail.
    return (*mem_bio_mem_ptr).data; //Returns base-64 encoded data. (See: "buf_mem_st" struct).
}

char *base64decode (const void *b64_decode_this, int decode_this_many_bytes){
    BIO *b64_bio, *mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
    char *base64_decoded = calloc( (decode_this_many_bytes*3)/4+1, sizeof(char) ); //+1 = null.
    b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
    mem_bio = BIO_new(BIO_s_mem());                         //Initialize our memory source BIO.
    BIO_write(mem_bio, b64_decode_this, decode_this_many_bytes); //Base64 data saved in source.
    BIO_push(b64_bio, mem_bio);          //Link the BIOs by creating a filter-source BIO chain.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);          //Don't require trailing newlines.
    int decoded_byte_index = 0;   //Index where the next base64_decoded byte should be written.
    while ( 0 < BIO_read(b64_bio, base64_decoded+decoded_byte_index, 1) ){ //Read byte-by-byte.
        decoded_byte_index++; //Increment the index until read of BIO decoded data is complete.
    } //Once we're done reading decoded data, BIO_read returns -1 even though there's no error.
    BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
    return base64_decoded;        //Returns base-64 decoded data with trailing null terminator.
}
/************************************* BASE-64 ENDED *****************************************/

int revt(int call, int reg_1, int reg_2){
	if(call == ADD)
		return reg_1 + reg_2;
	else if(call == SUB)
		return reg_1 - reg_2;
	else if(call == XOR)
		return reg_1 ^ reg_2;
	else
		return -1;
}

void run_dmc(char *base64_decoded_echeloncode, char user_buf[FLAG_SIZE]){
	int call = 0, reg_1 = 0, reg_2 = 0, result = 0, user_result = 0, no = 0, j = 0;
	for (int i = 0 ; i < CODE_SIZE ; i++){
 		call = base64_decoded_echeloncode[i];
		reg_1 = user_buf[j] & 0xff;
 		result = base64_decoded_echeloncode[i+1] & 0xff;
 		reg_2  = base64_decoded_echeloncode[i+2] & 0xff;
		user_result = revt(call, reg_1, reg_2);
		// printf("call: %x, reg_1: %x, reg_2: %x  result: %d user_result: %d ip: %d \n", call, reg_1, reg_2, result, user_result, i);
		if(user_result != result){
			no = 1;
			break;
		}
		i = i + 2;
		j = j + 1;
	}

	if(no == 0)
		puts("You know, I am something of a scientist myself!");
	else
		puts("meh, try again!");
}



int main(void){
    char *base64_encoded = "QEkgQCxYQm0MJghhJgJsJmETQtJlQDhNJgdcJgVjJlMPQn4JQp8rQFw0QFwzQA5gQqt\
GQEw/QtJeQtJbQrBBQr9NJhtQQoomQChHJgRqQtdjJnkAQr5PJg9mQH8LJl4KJjM2QClHQp80QC4P\0"; // echelonvm_code but its base64
		int bytes_to_decode = strlen(base64_encoded);

    char *base64_decoded = base64decode(base64_encoded, bytes_to_decode);   //Base-64 decoding to use byte by byte.
		char *password = "SSxtCAJh0jgHBVN+n1xcDqtM0tKwvxuKKATXeb4Pf14zKZ8u\0"; // password base64 encoded after ADD, SUB, XOR operations
		int pbytes_to_decode = strlen(password);

		char *decoded_password = base64decode(password, bytes_to_decode);

		char user_buf[FLAG_SIZE];
		puts("Can you provide the password?");
		while(read(0, user_buf, sizeof(user_buf))<FLAG_SIZE) {
			puts("Hmm hmm..");
		}
		run_dmc(base64_decoded, user_buf);
    free(base64_decoded);                //Frees up the memory holding our base64 decoded data.
}
