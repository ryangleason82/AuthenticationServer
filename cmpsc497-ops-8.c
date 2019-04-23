#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cmpsc497-format-8.h"
#include "cmpsc497-kvs.h"

#define KEY_LEN 49
#define VAL_LEN 48
#define TAG_LEN 48

int authorize(char *username, char *owner, char *op)
{
	unsigned char *key = (unsigned char *)malloc(KEY_LEN);
	unsigned char *val = (unsigned char *)malloc(VAL_LEN);
	unsigned char *tag = (unsigned char *)malloc(TAG_LEN);

	int rc;
	memset(key, 0, KEY_LEN);
	memcpy(key, username, strlen(username));
	memcpy(key + strlen(username), ":", 1);
	memcpy(key + strlen(username) + 1, owner, strlen(owner));
	memcpy(key + strlen(username) + strlen(owner) + 1, ":", strlen(owner));
	memcpy(key + strlen(username) + strlen(owner) + 2, op, strlen(owner));
	
	printf("\nAuthorization query: %s\n", key);
	rc = kvs_auth_get(Policy, key, &val, &tag);
	
	free(key);
	
	if(rc == 0){printf("Authorized: 1\n"); return 0;}
	else{printf("Not authorized: 0\n"); return 1;}
}

/*
	Requirements: 
	(a) Prevent any information flows from objects owned by subject T1 to subject T3
	(b) Other information flows are allowed
*/


int function_0(char *username, char *owner, struct A *objA)
{
	int b0 = objA->num_a;
	int c0 = objA->num_b;
	int sum = b0 + c0;
	struct B *objB = objA->ptr_c;
	struct C *objC = objA->ptr_h;
	int a1 = 0;
	int a2 = 0;
	int a3 = 0;
	int auth;
	
	auth = authorize(username, owner, "A1");
	if (auth != 0){
		printf("You are not authorized to access this information.\n");
		return 0;
	}
		
	//This will be defined by A1
	if (sum > 0) {
		
		/*
		This would be a redundant hook since already authorized
		auth = authorize(username, owner, "A1");
		if (auth != 0){
			printf("You are not authorized to access this information.\n");
			return 0;
		}
		*/

		int b = objA->num_a;
		int c = objA->num_b;
		int f = objA->num_e;
		int h = objA->num_g;
		a1 = b + c + f + h;
	}

	//This will be defined by B1
	else if (sum < 0) {
		
		/*
		This would be a redundant hook since already authorized
		auth = authorize(username, owner, "A1");
		if (auth != 0){
			printf("You are not authorized to access this information.\n");
			return 0;
		}
		*/
	
		int d = objB->num_c;
		int e = objB->num_d;
		int g = objB->num_f;
		a2 = d + e + g;
	}

	//This will be defined by C1
	else {
		
		/*
		This would be a redundant hook since already authorized
		auth = authorize(username, owner, "A1");
		if (auth != 0){
			printf("You are not authorized to access this information.\n");
			return 0;
		}
		*/

		int b = objC->num_a;
		int c = objC->num_b;
		int d = objC->num_c;
		a3 = b + c + d;
	}
	return(a1 + a2 + a3);
}

int function_1(char *username, char *owner, struct A *objA)
{

	int b0 = objA->num_a;
	int c0 = objA->num_b;
	int sum = b0 + c0;
	struct B *objB = objA->ptr_c;
	struct C *objC = objA->ptr_h;
	int a1 = 0;
	int a2 = 0;
	int a3 = 0;
	int auth;

	auth = authorize(username, owner, "A2");
	if (auth != 0){
		printf("You are not authorized to access this information.\n");
		return 0;
	}
	
	//This will be defined by A2
	if (sum > 0) {
		
		/*
		This would be a redundant hook since already authorized
		auth = authorize(username, owner, "A2");
		if (auth != 0){
			printf("You are not authorized to access this information.\n");
			return 0;
		}
		*/

		int e = strlen(objA->string_d);
		int g = strlen(objA->string_f);
		a1 = e + g;
	}

	//This will be defined by B2
	else if (sum < 0) {
		/*
		This would be a redundant hook since already authorized
		auth = authorize(username, owner, "A2");
		if (auth != 0){
			printf("You are not authorized to access this information.\n");
			return 0;
		}
		*/

		int b = strlen(objB->string_a);
		int c = strlen(objB->string_b);
		int f = strlen(objB->string_e);
		a2 = b + c + f;
	}

	//This will be defined by C2
	else {
		/*
		This would be a redundant hook since already authorized
		auth = authorize(username, owner, "A2");
		if (auth != 0){
			printf("You are not authorized to access this information.\n");
			return 0;
		}
		*/

		int e = strlen(objC->string_d);
		int f = strlen(objC->string_e);
		a3 = e + f;
	}
	return(a1 + a2 + a3);
}

int function_2(char *username, char *owner, struct A *objA)
{
	int b0 = objA->num_a;
	int c0 = objA->num_b;
	int sum = b0 + c0;
	struct B *objB = objA->ptr_c;
	struct C *objC = objA->ptr_h;
	int a1 = 0;
	int a2 = 0;
	int a3 = 0;
	int auth;
	
	auth = authorize(username, owner, "A3");
	if (auth != 0){
		printf("You are not authorized to access this information.\n");
		return 0;
	}

	//This will be defined by A1 as well
	//Since A1 will have access to these two variables
	if (sum > 0) {
		
		/*
		This would be a redundant hook since already authorized
		auth = authorize(username, owner, "A3");
		if (auth != 0){
			printf("You are not authorized to access this information.\n");
			return 0;
		}
		*/

		int b = objA->num_a;
		int c = objA->num_b;
		a1 = b + c;
	}

	//This will be defined by B2 
	//Since B1 will have access to these two variables 
	else if (sum < 0) {
		/*
		This would be a redundant hook since already authorized
		auth = authorize(username, owner, "A3");
		if (auth != 0){
			printf("You are not authorized to access this information.\n");
			return 0;
		}
		*/

		int b = strlen(objB->string_a);
		int c = strlen(objB->string_b);
		//printf("\n%b \n%c", b, c);
		a2 = b + c;
	}

	//This will be defined by C1 as well
	else {
		
		/*
		This would be a redundant hook since already authorized
		auth = authorize(username, owner, "A3");
		if (auth != 0){
			printf("You are not authorized to access this information.\n");
			return 0;
		}
		*/


		int b = objC->num_a;
		int c = objC->num_b;
		a3 = b + c;
	}
	return(a1 + a2 + a3);
}

