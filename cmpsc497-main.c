#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include "cmpsc497-kvs.h"
#include "cmpsc497-ssl.h"
#include "cmpsc497-format-8.h"   // student-specific

/* Defines */
#define NAME_LEN    16
#define SALT_LEN    16
#define HASH_LEN    32
#define PWD_LEN     (HASH_LEN-SALT_LEN)
#define OBJ_LEN     152  // marshall says 236  // size of object tree for this project
#define KEY_LEN     8
#define QUERY_LEN   48
#define PADDING     "----"
#define RESULT_LEN  4
#define PAD_LEN     4
#define LINE_SIZE   100

#define PASSWDS_PATH "./passwds-file"
#define OBJECTS_PATH "./objects-file"
#define POLICY_PATH "./policy-file"

struct kvs *Passwds;
struct kvs *Objects;
struct kvs *Policy;


/* Project APIs */
// public 
extern int set_password( char *username, char *password );
extern int set_object( char *filename, char *username, char *password );
extern int get_object( char *cmd, char *username, char *password, char *id );
extern int set_policy( char *filename, char *username, char *password );

// internal
extern int unknown_user( char *username );
extern int authenticate_user( char *username, char *password );
extern struct A *upload_A( FILE *fp );
extern struct B *upload_B( FILE *fp );
extern struct C *upload_C( FILE *fp );
extern struct D *upload_D( FILE *fp );
extern struct E *upload_E( FILE *fp );
extern struct F *upload_F( FILE *fp );
extern unsigned char *marshall( struct A *objA );
extern struct A *unmarshall( unsigned char *obj );
extern int output_obj( struct A *objA, char *id );
extern int kvs_dump( struct kvs *kvs, char *filepath, unsigned int keysize, 
		     unsigned int valsize, unsigned int tagsize );
int checkNumber(char *string);
int checkField(char **string);
int checkAlphabet(char *string);
int breakup(char *policy, int *val);

// for function pointers
extern int function_0( char *username, char *owner, struct A *objA );
extern int function_1( char *username, char *owner, struct A *objA );
extern int function_2( char *username, char *owner, struct A *objA );


/*****************************

Invoke:
cmpsc497-p1 set user-name password obj-file
cmpsc497-p1 get<0-2> user-name password obj-id
cmpsc497-p1 pol user-name password obj-id

Commands:
<set_password> user-name password 
<set_object> user-name password obj-file
<get_object> user-name password obj-id
<get_policy> user-name password pol-file

1 - set password - user name and password
    compute random salt and hash the salt+password

2 - set object - authenticate user for command
    and enter object into object store 

3 - get-object - authenticate user for command
    and retrieve object from object store by id

Object store - array of objects - base object reference and password hash

Need to dump objects and password hashes to file(s)

******************************/


int main( int argc, char *argv[] )
{
	int rtn;

	assert( argc == 5 );

	crypto_init();  // Necessary for hashing?
	ENGINE *eng = engine_init();

	/* initialize KVS from file */
	Passwds = (struct kvs *)malloc(sizeof(struct kvs));
	Objects = (struct kvs *)malloc(sizeof(struct kvs));
	Policy = (struct kvs *)malloc(sizeof(struct kvs));
	kvs_init( Passwds, PASSWDS_PATH, NAME_LEN, HASH_LEN, HASH_LEN, PAD_LEN );
	kvs_init( Objects, OBJECTS_PATH, KEY_LEN, OBJ_LEN, NAME_LEN, PAD_LEN );  // OBJ_LEN - size of the object tree for this project
	kvs_init( Policy, POLICY_PATH, QUERY_LEN, RESULT_LEN, PAD_LEN, PAD_LEN ); 

	if ( strncmp( argv[1], "set", 3 ) == 0 ) {
		if ( unknown_user( argv[2] )) {
			rtn = set_password( argv[2], argv[3] );
			assert( rtn == 0 );
		}
		rtn = set_object( argv[4], argv[2], argv[3] );
	}
	else if ( strncmp( argv[1], "get", 3 ) == 0 ) {
		rtn = get_object( argv[1], argv[2], argv[3], argv[4] );
	}
	else if ( strncmp( argv[1], "pol", 3 ) == 0 ) {
	  rtn = set_policy( argv[4], argv[2], argv[3] );
	}
	else {
		printf( "Unknown command: %s\nExiting...\n", argv[1] );
		exit(-1);
	}

	kvs_dump( Passwds, PASSWDS_PATH, NAME_LEN, HASH_LEN, HASH_LEN ); 
	kvs_dump( Objects, OBJECTS_PATH, KEY_LEN, OBJ_LEN, NAME_LEN ); 
	kvs_dump( Policy, POLICY_PATH, QUERY_LEN, RESULT_LEN, PAD_LEN ); 

	crypto_cleanup();
	engine_cleanup( eng );
  
	exit(0);
}

/*
Objectives:
1. Takes file with authorized operations
	Add those authorizations to the Policy KVS
	Each operation entry is of format: username:owner:op
	username: name of the user making get request
	owner: owner of the object retrieved from KVS for operation
	op: name of the operation
		example ops: Ax, Bx, Cx
			A refers to sructure accesses
			x is a number to differentiate multiple cases
2. Return 1 or 0 
	1 - allowed
	0 - not

3. Tag can be set to any value. 


*/
//<get_policy> user-name password pol-file

int set_policy( char *filename, char *username, char *password )
{
	FILE *fp = (FILE *) NULL;
	char *buf = (char *)malloc(LINE_SIZE);
	unsigned char *tag = (unsigned char *)malloc(48);
	unsigned char *auth = (unsigned char *)malloc(8);
	unsigned char *key = (unsigned char *)malloc(LINE_SIZE);
	
	assert( strlen( password ) <= PWD_LEN );
	assert( strlen( username ) <= NAME_LEN );

	if ( !authenticate_user( username, password )) {
		fprintf(stderr, "set_policy authentication failed %s:%s\n", username, password );
		return -1;
	}

	fp = fopen( filename, "r" );  // read input
	assert( fp != NULL ); 

	memset(tag, 0, 8);
	memset(auth, 0, 8);
	memcpy(tag, "0", 1);
	memcpy(auth, "1", 1);
	
	memset(buf, 0, LINE_SIZE);
	while(fscanf(fp, "%ms", &buf) == 1){
		printf("%s\n", buf);
		memset(key, 0, LINE_SIZE);
		memcpy(key, buf, strlen(buf));
		kvs_auth_set(Policy, key, auth, tag);
		free(buf);
		memset(buf, 0, strlen(buf));
	}

	return 0;
}

//break key into pieces. This actually wasn't a necessary function
int breakup(char *policy, int *val){
	
	int i, j, k;
	i = 0, j = 0, k = 0;
	char *uname = (char *)malloc(16);
	char *owner = (char *)malloc(16);
	char *op = (char *)malloc(16);
	memset(uname, 0, sizeof(uname)); 
	memset(owner, 0, sizeof(owner));
	memset(op, 0, sizeof(op));
	
	//Assumptions: of form [username]:[obj_owner]:[op]
	//op is 2 characters
	while(policy[i] != ':'){
		uname[i] += policy[i];
		i++;
	}i++;
	while(policy[i] != ':'){
		owner[j] += policy[i];
		i++; j++;
	}i++;
	while(k != 2){
		op[k] += policy[i];
		k++; i++;
	}
	
	//*val = authorize(uname, owner, op);

	
	return 0;
}


int set_password( char *a, char *b )
{ 
	unsigned char *tag = (unsigned char *)malloc(SALT_LEN);
	unsigned char *hash = (unsigned char *)malloc(HASH_LEN);
	unsigned char *value = (unsigned char *)malloc(HASH_LEN);
	unsigned char *key = (unsigned char *)malloc(NAME_LEN);
	unsigned int digest_length = HASH_LEN;
	size_t hash_length = HASH_LEN;
	
	//Populate hash with salt, password and null characters
	memset(key, 0, NAME_LEN);
	RAND_bytes(tag, SALT_LEN);
	memset(hash, '\0', HASH_LEN);
	memcpy(key, a, strlen(a));
	memcpy(hash, tag, strlen((char *)tag));
	memcpy(hash + SALT_LEN, b, strlen(b));
	
	//Create empty buffer to store digest
	memset(value, '\0', 32);

	//Generate digest 
	digest_message(hash, hash_length, &value, &digest_length);
	
	kvs_auth_set(Passwds, key, value, tag);
	
	free(hash);
	free(tag);
	free(value);
	free(key);

	return 0;
}


/**********************************************************************

    Function    : unknown_user
    Description : Check if username corresponds to entry in Passwds KVS
    Inputs      : username - username string from user input
    Outputs     : non-zero if true, NULL (0) if false

***********************************************************************/

int unknown_user( char *username )
{
	unsigned char *hash = (unsigned char *)malloc(HASH_LEN);
	unsigned char *salt = (unsigned char *)malloc(SALT_LEN);
	unsigned char *name = (unsigned char *)malloc(NAME_LEN);

	assert( strlen( username ) <= NAME_LEN );

	memset( name, 0, NAME_LEN );
	memcpy( name, username, strlen(username) );

	return( kvs_auth_get( Passwds, name, &hash, &salt ));
}


/**********************************************************************

    Function    : authenticate_user
    Description : Lookup username entry in Passwds KVS
                  Compute password hash with input password using stored salt
                  Must be same as stored password hash for user to authenticate
    Inputs      : username - username string from user input
                  password - password string from user input
    Outputs     : non-zero if authenticated, 0 otherwise

***********************************************************************/

int authenticate_user( char *username, char *password )
{
	int ret;
	unsigned char *salt = (unsigned char *)malloc(SALT_LEN);
	unsigned char *value = (unsigned char *)malloc(HASH_LEN);
	unsigned char *name = (unsigned char *)malloc(NAME_LEN);
	unsigned char *hash = (unsigned char *)malloc(HASH_LEN);
	unsigned char *newVal = (unsigned char *)malloc(HASH_LEN);
	unsigned int digest_length = HASH_LEN;
	size_t hash_length = HASH_LEN;
	
	//zero out buffers
	memset(name, 0, NAME_LEN);
	memset(newVal, 0, HASH_LEN);
	memset(hash, 0, HASH_LEN);
	memset(value, 0, HASH_LEN);
	memset(salt, 0, SALT_LEN);
	
	//Change type of name and retrieve value and salt 
	memcpy(name, username, strlen(username));

	//retrieve the value and salt from associated username
	ret = kvs_auth_get(Passwds, name, &value, &salt);
	if(ret != 0){
		printf("Username was not found in KVS");
		return 0;
	}
		
	//Generate hash using given password and retrieved salt
	memcpy(hash, salt, strlen((char *)salt));
	memcpy(hash + SALT_LEN, password, strlen(password));

	//calculate password 
	digest_message(hash, hash_length, &newVal, &digest_length);
	
	//compare passwords
	if (strncmp((const char *)value, (const char *)newVal, HASH_LEN) == 0){
		return -1;
	}
	else{
		printf("The password did not exist");
		return 0;
	}

}

/**********************************************************************

    Function    : set_object
    Description : Authenticate user with username and password
                  If authenticated, read input from filename file
                  Upload each structure by calling upload_X for struct X
    Inputs      : filename - containing object data to upload
                  username - username string from user input
                  password - password string from user input
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int set_object( char *filename, char *username, char *password )
{
	
	if ( !authenticate_user( username, password )) {
		fprintf(stderr, "get_object authentication failed %s:%s\n", username, password );
		return -1;
	}
	
	unsigned char *key = (unsigned char *)malloc(KEY_LEN);
	unsigned char *val = (unsigned char *)malloc(OBJ_LEN);
	unsigned char *tag = (unsigned char *)malloc(NAME_LEN);
	char *str1, *str2, *str3;
	struct A *objA;
	
	//set buffers to 0
	memset(tag, 0, NAME_LEN);
	memcpy(tag, username, strlen(username));
	memset(key, 0, KEY_LEN);
	
	//Read key from file to send to KVS
	FILE *fp;
	fp = fopen(filename, "r");
	fscanf(fp, "%ms %ms %ms", &str1, &str2, &str3);
	fclose(fp);
	
	if(checkNumber(str3) == -1){
		printf("Not a valid ID\n");
		return -1;
	}
	
	memcpy(key, str3, strlen(str3));

	//Start upload of object
	fp = fopen(filename, "r");		
	objA = upload_A(fp);
	
	//Load linearized object to send to KVS
	val = marshall(objA);
	kvs_auth_set(Objects, key, val, tag);
	
	//int funRet;
	int (*op0)(char *username, char *owner, struct A *objA);
	int (*op1)(char *username, char *owner, struct A *objA);
	int (*op2)(char *username, char *owner, struct A *objA);
	op0 = &function_0;
	op1 = &function_1;
	op2 = &function_2;
	//funRet = op1(" ", " ", objA);
	//printf("\n%d\n", funRet);
	
	free(key);
	free(val);
	free(tag);

	return 0;
}




int get_object( char *cmd, char *username, char *password, char *id )
{
	unsigned char *key = (unsigned char *)malloc(KEY_LEN);
	unsigned char *owner, *obj;
	int rc;
	struct A *objA;
	int (*op0)(char *username, char *owner, struct A *objA);
	int (*op1)(char *username, char *owner, struct A *objA);
	int (*op2)(char *username, char *owner, struct A *objA);
	op0 = &function_0;
	op1 = &function_1;
	op2 = &function_2;

	//struct A *objA;

	assert( strlen( password ) <= PWD_LEN );
	assert( strlen( username ) <= NAME_LEN );
	assert( strlen(id) <= KEY_LEN );  

	if ( !authenticate_user( username, password )) {
		fprintf(stderr, "get_object authentication failed %s:%s\n", username, password );
		return -1;
	}

	memset( key, 0, KEY_LEN );
	memcpy( key, id, strlen(id) );

	rc = kvs_auth_get( Objects, key, &obj, &owner );
 
	if ( rc == 0 ) {  // found object
		int rtn;

		objA = unmarshall( obj );
		
		if ( strncmp( cmd, "get0", 4 ) == 0 ) {
			rtn = op0( username, (char *)owner, objA );
			printf( "%s : result = %d\n", cmd, rtn );
		}
		else if ( strncmp( cmd, "get1", 4 ) == 0 ) {
			rtn = op1( username, (char *)owner, objA );
			printf( "%s : result = %d\n", cmd, rtn );
		}
		else if ( strncmp( cmd, "get2", 4 ) == 0 ) {
			rtn = op2( username, (char *)owner, objA );
			printf( "%s : result = %d\n", cmd, rtn );
		}
		else {
			fprintf(stderr, "get_object : unrecognized command %s\n", cmd );
		}
	}
	else {
		fprintf(stderr, "get_object failed to return object for key: %s\n", id );
		return -1;
	}

	return 0;
}


/**********************************************************************

    Function    : upload_A 
    Description : For each line in file referenced by fp 
                  Assign value to struct field for object A (ints and strings)
                  or call upload_X function to upload data for struct X
    Inputs      : fp - file pointer for object input file
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

struct A *upload_A( FILE *fp ){
	
	struct A *objA = (struct A *)malloc(sizeof(struct A));
	char *num_a, *num_b, *num_e, *num_g;
	char *string_d, *string_f;
	char *ptr_c, *ptr_h;
	char *str1, *str2, *id, *str3, *str4, *str5, *str6, *str7, *str8, *str9, *str10, *str11, *str12, *str13, *str14, *str15, *str16, *str17, *str18;

	if (fp == NULL){
		printf("nothing existed in that file");
	}
	
	fscanf(fp, "%ms %ms %ms", &str1, &str2, &id);
	if(checkAlphabet(str1)) *str1 = '\0';
	if(checkAlphabet(str2)) *str2 = '\0';
	fscanf(fp, "%ms %ms %ms", &str3, &str4, &num_a);
		if(checkNumber(num_a) == 0) objA->num_a = atoi(num_a);
		else objA->num_a = 0;
		if(checkAlphabet(str3)) *str3 = '\0';
		if(checkAlphabet(str4)) *str4 = '\0';
		checkField(&str3);

	fscanf(fp, "%ms %ms %ms", &str5, &str6, &num_b);
		if(checkNumber(num_b) == 0){
			objA->num_b = atoi(num_b);
			if(objA->num_b < 0)objA->num_b = 0;
		}
		else objA->num_b = 0;
		if(checkAlphabet(str5)) *str5 = '\0';
		if(checkAlphabet(str6)) *str6 = '\0';
		checkField(&str5);
		
	fscanf(fp, "%ms %ms %ms", &str7, &str8, &ptr_c);
		if(checkAlphabet(str7)) *str7 = '\0';
		if(checkAlphabet(str8)) *str8 = '\0';
		checkField(&str7);
	
	fscanf(fp, "%ms %ms %ms", &str9, &str10, &string_d);
		strcpy(objA->string_d, string_d);
		if(checkAlphabet(str9)) *str9 = '\0';
		if(checkAlphabet(str10)) *str10 = '\0';
		checkField(&str9);

	fscanf(fp, "%ms %ms %ms", &str11, &str12, &num_e);
		if(checkNumber(num_e) == 0) objA->num_e = atoi(num_e);
		else objA->num_e = 0;
		if(checkAlphabet(str11)) *str11 = '\0';
		if(checkAlphabet(str12)) *str12 = '\0';
		checkField(&str11);
	
	fscanf(fp, "%ms %ms %ms", &str13, &str14, &string_f);
		strcpy(objA->string_f, string_f);
		if(checkAlphabet(str13)) *str13 = '\0';
		if(checkAlphabet(str14)) *str14 = '\0';
		checkField(&str13);
	
	fscanf(fp, "%ms %ms %ms", &str15, &str16, &num_g);
		if(checkNumber(num_g) == 0){
			objA->num_g = atoi(num_g);
			if(objA->num_g < 0)objA->num_g = 0;
		}
		else objA->num_g = 0;
		if(checkAlphabet(str15)) *str15 = '\0';
		if(checkAlphabet(str16)) *str16 = '\0';
		checkField(&str15);

	fscanf(fp, "%ms %ms %ms", &str17, &str18, &ptr_h);
		if(checkAlphabet(str17)) *str17 = '\0';
		if(checkAlphabet(str18)) *str18 = '\0';
		checkField(&str17);
	
	//Upload structs B and C into ptr_c and ptr_h respectively 
	objA->ptr_c = upload_B(fp);
	objA->ptr_h = upload_C(fp);
	
	return objA;
}


/**********************************************************************

    Function    : upload_B 
    Description : For each line in file referenced by fp 
                  Assign value to struct field for object A (ints and strings)
                  or call upload_X function to upload data for struct X
    Inputs      : fp - file pointer for object input file
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

struct B *upload_B( FILE *fp )
{	
	struct B *objB = (struct B *)malloc(sizeof(struct B));
	char *num_c, *num_d, *num_f;
	char *string_a, *string_b, *string_e;
	char *str1, *str2, *id, *str3, *str4, *str5, *str6, *str7, *str8, *str9, *str10, *str11, *str12, *str13, *str14;
	
	fscanf(fp, "%ms %ms %ms", &str1, &str2, &id);
		if(checkAlphabet(str1)) *str1 = '\0';
		if(checkAlphabet(str2)) *str2 = '\0';
	fscanf(fp, "%ms %ms %ms", &str3, &str4, &string_a);
		if(checkAlphabet(str3)) *str3 = '\0';
		if(checkAlphabet(str4)) *str4 = '\0';
		strcpy(objB->string_a, string_a);
		checkField(&str3);
		
	fscanf(fp, "%ms %ms %ms", &str5, &str6, &string_b);
		if(checkAlphabet(str5)) *str5 = '\0';
		if(checkAlphabet(str6)) *str6 = '\0';
		strcpy(objB->string_b, string_b);
		checkField(&str5);
	fscanf(fp, "%ms %ms %ms", &str7, &str8, &num_c);
		if(checkNumber(num_c) == 0){
			objB->num_c = atoi(num_c);
			if(objB->num_c < 0)objB->num_c = 0;
		}
		else objB->num_c = 0;
		if(checkAlphabet(str7)) *str7 = '\0';
		if(checkAlphabet(str8)) *str8 = '\0';
		checkField(&str7);

	fscanf(fp, "%ms %ms %ms", &str9, &str10, &num_d);
		if(checkNumber(num_d) == 0) objB->num_d = atoi(num_d);
		else objB->num_d = 0;
		if(checkAlphabet(str9)) *str9 = '\0';
		if(checkAlphabet(str10)) *str10 = '\0';
		checkField(&str9);

	fscanf(fp, "%ms %ms %ms", &str11, &str12, &string_e);
		if(checkAlphabet(str11)) *str11 = '\0';
		if(checkAlphabet(str12)) *str12 = '\0';
		strcpy(objB->string_e, string_e);
		checkField(&str11);
		
	fscanf(fp, "%ms %ms %ms", &str13, &str14, &num_f);
		if(checkNumber(num_f) == 0){
			objB->num_f = atoi(num_f);
			if(objB->num_f > 0)objB->num_f = 0;
		}
		else objB->num_f = 0;
		if(checkAlphabet(str13)) *str13 = '\0';
		if(checkAlphabet(str14)) *str14 = '\0';
		checkField(&str13);
	
	return objB;
}


/**********************************************************************

    Function    : upload_C
    Description : For each line in file referenced by fp 
                  Assign value to struct field for object A (ints and strings)
                  or call upload_X function to upload data for struct X
    Inputs      : fp - file pointer for object input file
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

struct C *upload_C( FILE *fp )
{		
	struct C *objC = (struct C *)malloc(sizeof(struct C));
	char *num_a, *num_b, *num_c;
	char *string_d, *string_e;
	char *str1, *str2, *id, *str3, *str4, *str5, *str6, *str7, *str8, *str9, *str10, *str11, *str12;
	
	fscanf(fp, "%ms %ms %ms", &str1, &str2, &id);
		if(checkAlphabet(str1)) *str1 = '\0';
		if(checkAlphabet(str2)) *str2 = '\0';
		
	fscanf(fp, "%ms %ms %ms", &str3, &str4, &num_a);
		if(checkNumber(num_a) == 0) objC->num_a = atoi(num_a);
		else objC->num_a = 0;
		if(checkAlphabet(str3)) *str3 = '\0';
		if(checkAlphabet(str4)) *str4 = '\0';
		checkField(&str3);

	fscanf(fp, "%ms %ms %ms", &str5, &str6, &num_b);
		if(checkNumber(num_b) == 0){
			objC->num_b = atoi(num_b);
			if(objC->num_b < 0)objC->num_b = 0;
		}
		else objC->num_b = 0;
		if(checkAlphabet(str5)) *str5 = '\0';
		if(checkAlphabet(str6)) *str6 = '\0';
		checkField(&str5);

	fscanf(fp, "%ms %ms %ms", &str7, &str8, &num_c);
		if(checkNumber(num_c) == 0){
			objC->num_c = atoi(num_c);
			if(objC->num_c < 0)objC->num_c = 0;
		}
		else objC->num_c = 0;
		if(checkAlphabet(str7)) *str7 = '\0';
		if(checkAlphabet(str8)) *str8 = '\0';
		checkField(&str7);
				
	fscanf(fp, "%ms %ms %ms", &str9, &str10, &string_d);
		strcpy(objC->string_d, string_d);
		if(checkAlphabet(str9)) *str9 = '\0';
		if(checkAlphabet(str10)) *str10 = '\0';
		checkField(&str9);

	fscanf(fp, "%ms %ms %ms", &str11, &str12, &string_e);
		if(checkAlphabet(string_e)) *string_e = '\0';
		strncpy(objC->string_e, string_e, strlen((const char *)string_e));
		if(checkAlphabet(str11)) *str11 = '\0';
		if(checkAlphabet(str12)) *str12 = '\0';
		
		checkField(&str11);
	
	return objC;
}

//Input Validation Functions
int checkNumber(char *string){
	int i;
	if(string[0] == '-'){
		for (i = 1; i<strlen(string); i++){
			if (isdigit(string[i])==0) break;}
		if (i != strlen(string)) return -1;
		else return 0;
		}

	else{
		for (i = 0; i<strlen(string); i++){
			if (isdigit(string[i])==0) break;}	
		if (i != strlen(string)) return -1;
		else return 0;
	}	
}

int checkField(char **string){
	if (strcmp("field", (const char *)string)!= 0) *string = "field";
	return 0;
}

int checkAlphabet(char *string){
		int i;
		for (i = 0; i<strlen(string); i++)
			if(isalpha(string[i]) == 0) break;
		if (i !=strlen(string)) return -1;
		else return 0;
				
	return 0;
}
	

/**********************************************************************

    Function    : marshall
    Description : serialize the object data to store in KVS
            *** Below an example is provided for a different object structure ***
            *** Adapt for your object structure ***
    Inputs      : objA - reference to root structure of object
    Outputs     : unsigned char string of serialized object

***********************************************************************/

unsigned char *marshall( struct A *objA )
{
	unsigned char *obj = (unsigned char *)malloc(OBJ_LEN);

	//Linearize the object tree
	memcpy( obj, &(objA->num_a), sizeof(objA->num_a) );
	memcpy( obj+sizeof(objA->num_a), &(objA->num_b), sizeof(objA->num_b) ); 
	memcpy( obj+sizeof(objA->num_a)+sizeof(objA->num_b), objA->ptr_c, sizeof(struct B) );
	memcpy( obj+sizeof(objA->num_a)+sizeof(objA->num_b)+sizeof(struct B), objA->string_d, sizeof(objA->string_d) );
	memcpy( obj+sizeof(objA->num_a)+sizeof(objA->num_b)+sizeof(struct B)+sizeof(objA->string_d), &(objA->num_e), sizeof(objA->num_e) );
	memcpy( obj+sizeof(objA->num_a)+sizeof(objA->num_b)+sizeof(struct B)+sizeof(objA->string_d)+sizeof(objA->num_e), objA->string_f, sizeof(objA->string_f) );
	memcpy( obj+sizeof(objA->num_a)+sizeof(objA->num_b)+sizeof(struct B)+sizeof(objA->string_d)+sizeof(objA->num_e)+sizeof(objA->string_f), &(objA->num_g), sizeof(objA->num_g) );
	memcpy( obj+sizeof(objA->num_a)+sizeof(objA->num_b)+sizeof(struct B)+sizeof(objA->string_d)+sizeof(objA->num_e)+sizeof(objA->string_f)+sizeof(objA->num_g), objA->ptr_h, sizeof(struct C) );
	printf("Size of object = %lu\n", sizeof(objA->num_a)+sizeof(objA->num_b)
									+sizeof(struct B)+sizeof(objA->string_d)+sizeof(objA->num_e)
									+sizeof(objA->string_f)+sizeof(objA->num_g)+sizeof(struct C));
	return obj;
}


/**********************************************************************

    Function    : unmarshall
    Description : convert a serialized object into data structure form
            *** Below an example is provided for a different object structure ***
            *** Adapt for your object structure ***
    Inputs      : obj - unsigned char string of serialized object
    Outputs     : reference to root structure of object

***********************************************************************/

struct A *unmarshall( unsigned char *obj )
{
	struct A *objA = (struct A *)malloc(sizeof(struct A));
	struct B *objB = (struct B *)malloc(sizeof(struct B));
	struct C *objC = (struct C *)malloc(sizeof(struct C));
	int (*op0)(char *username, char *owner, struct A *objA);
	int (*op1)(char *username, char *owner, struct A *objA);
	int (*op2)(char *username, char *owner, struct A *objA);
	op0 = &function_0;
	op1 = &function_1;
	op2 = &function_2;

	//Turn object back into tree
	memcpy( &(objA->num_a), obj, sizeof(objA->num_a) ); 
	memcpy( &(objA->num_b), obj+sizeof(objA->num_a), sizeof(objA->num_b));
	memcpy( objB, obj+sizeof(objA->num_a)+sizeof(objA->num_b), sizeof(struct B));
	memcpy( &(objA->string_d), obj+sizeof(objA->num_a)+sizeof(objA->num_b)+sizeof(struct B), sizeof(objA->string_d));
	memcpy( &(objA->num_e), obj+sizeof(objA->num_a)+sizeof(objA->num_b)+sizeof(struct B)+sizeof(objA->string_d), sizeof(objA->num_e));
	memcpy( &(objA->string_f), obj+sizeof(objA->num_a)+sizeof(objA->num_b)+sizeof(struct B)+sizeof(objA->string_d)+sizeof(objA->num_e), sizeof(objA->string_f));
	memcpy( &(objA->num_g), obj+sizeof(objA->num_a)+sizeof(objA->num_b)+sizeof(struct B)+sizeof(objA->string_d)+sizeof(objA->num_e)+sizeof(objA->string_f), sizeof(objA->num_g));
	memcpy( objC, obj+sizeof(objA->num_a)+sizeof(objA->num_b)+sizeof(struct B)+sizeof(objA->string_d)+sizeof(objA->num_e)+sizeof(objA->string_f)+sizeof(objA->num_g), sizeof(struct C));
	
	objA->ptr_c = objB;
	objA->ptr_h = objC;

	return objA;
}


/**********************************************************************

    Function    : output_obj
    Description : print int and string fields from structs A, B, and last
            *** Below an example is provided for a different object structure ***
            *** Adapt for your object structure ***
    Inputs      : objA - reference to root structure of object
                  id - identifier for the object
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int output_obj( struct A *objA, char *id )
{
	// Base object fields
	printf("ObjA: %s\n", id );
	printf("ObjA -> num_a: %d\n", objA->num_a );
	printf("ObjA -> num_b: %d\n", objA->num_b );
	printf("ObjA -> string_d: %s\n", objA->string_d );
	printf("ObjA -> num_e: %d\n", objA->num_e );
	printf("ObjA -> string_f: %s\n", objA->string_f );
	printf("ObjA -> num_g: %d\n", objA->num_g );

	// First sub-object fields
	printf("ObjB -> string_a: %s\n", objA->ptr_c->string_a );
	printf("ObjB -> string_b: %s\n", objA->ptr_c->string_b );
	printf("ObjB -> num_c: %d\n", objA->ptr_c->num_c );
	printf("ObjB -> num_d: %d\n", objA->ptr_c->num_d );
	printf("ObjB -> string_e: %s\n", objA->ptr_c->string_e );
	printf("ObjB -> num_f: %d\n", objA->ptr_c->num_f );

	// Last sub-object fields
	printf("ObjC -> num_a: %d\n", objA->ptr_h->num_a );
	printf("ObjC -> num_b: %d\n", objA->ptr_h->num_b );
	printf("ObjC -> num_c: %d\n", objA->ptr_h->num_c );
	printf("ObjC -> string_d: %s\n", objA->ptr_h->string_d );
	printf("ObjC -> string_e: %s\n", objA->ptr_h->string_e );

	return 0;
}

/**********************************************************************

    Function    : kvs_dump
    Description : dump the KVS to a file specified by path
    Inputs      : kvs - key value store
                  path - file path to dump KVS
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int kvs_dump( struct kvs *kvs, char *path, unsigned int keysize, unsigned int valsize, unsigned int tagsize )
{
	int i;
	struct kv_list_entry *kvle;
	struct authval *av;
	struct kvpair *kvp;
	FILE *fp = fopen( path, "w+" ); 

	assert( fp != NULL );

	for (i = 0; i < KVS_BUCKETS; i++) {
		kvle = kvs->store[i];
      
		while ( kvle != NULL ) {
			kvp = kvle->entry;
			av = kvp->av;

			fwrite((const char *)kvp->key, 1, kvs->keysize, fp);
			fwrite((const char *)av->value, 1, kvs->valsize, fp);
			fwrite((const char *)av->tag, 1, kvs->tagsize, fp);
			fwrite((const char *)PADDING, 1, PAD_LEN, fp);
	
			// Next entry
			kvle = kvle->next;
		}
	}
	return 0;
}
