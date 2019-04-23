#define STRLEN   16

struct A {
	int num_a; // Any integer
	int num_b; // >0 or set to 0
	struct B *ptr_c; // 
	char string_d[STRLEN]; // Capitalize Strings
	int num_e; // Any integer
	char string_f[STRLEN]; // Must have vowel or add to end
	int num_g; // >0 or set to 0
	struct C *ptr_h; // 
	int (*op0)(char *username, char *owner, struct A *objA);
	int (*op1)(char *username, char *owner, struct A *objA);
	int (*op2)(char *username, char *owner, struct A *objA);
};
struct B {
	char string_a[STRLEN]; // Capitalize Strings
	char string_b[STRLEN]; // Capitalize Strings
	int num_c; // >0 or set to 0
	int num_d; // Any integer
	char string_e[STRLEN]; // Must have vowel or add to end
	int num_f; // <0 or set to 0
};
struct C {
	int num_a; // Any integer
	int num_b; // >0 or set to 0
	int num_c; // >0 or set to 0
	char string_d[STRLEN]; // Must have vowel or add to end
	char string_e[STRLEN]; // Must have vowel or add to end
};
