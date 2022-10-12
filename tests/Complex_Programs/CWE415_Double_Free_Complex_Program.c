#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdbool.h>
#define def_user "u-admin-"
#define def_pass "password"
void signup(char *username, char *password)
{
	/* Uncomment the following two lines for heap-based buffer overflow & use-after-free & double-free */
	char* tmp_user = (char *)(malloc(50*sizeof(char)));
	char* tmp_pass = (char *)(malloc(50*sizeof(char)));
	/* Uncomment the following line for stack-based buffer overflow */
	// char tmp_user[16], tmp_pass[16];
	if((username[1] >= '0' && username[1] <= '9') && !strncmp(password, "passW0rd", 8))
	{ 
		/* POTENTIAL FLAW: data may not have enough space to hold source */
		/* Uncomment the following line for heap-based & stack-based buffer overflow */
		// memcpy(tmp_user, username, strlen(username));
		/* POTENTIAL FLAW: data may not have enough space to hold source */
		/* Uncomment the following line for heap-based & stack-based buffer overflow */
		// memcpy(tmp_pass, password, strlen(password));
		if(strlen(tmp_pass) < 12) 
		{ 
			printf("The selected password is too weak\n"); 
			return; 
		}
		int fd = open(tmp_user, O_WRONLY|O_CREAT, 0777);
		if(fd < 0) 
		{ 
			printf("An unexpected problem occurred!\n");
			return; 
		}
		write(fd,tmp_pass, sizeof(tmp_pass));
		printf("%s your registration was successful\n", tmp_user);
		/* POTENTIAL FLAW: Free data here - line 30 frees data as well */
 		/* Uncomment the following line for double-free */
		free(tmp_user); free(tmp_pass);
	}
	else if(!(username[1] >= '0' && username[1] <= '9')) 
	{
		printf("The second letter of username must be a number\n");
	}
	else 
	{ 
		printf("The password must start with the word <passW0rd>\n"); 
	}
	/* Uncomment the following line for double-free & use-after-free & heap-based buffer overflow */
	free(tmp_user);	free(tmp_pass);
	/* POTENTIAL FLAW: Use of data that may have been freed in line 30 */ 
	/* Uncomment the following line for use-after-free */
	// tmp_user[50-1] = '\0'; tmp_pass[50-1] = '\0';
}
bool check(char *username, char *password)
{
	/* Uncomment the following two lines for heap-based buffer overflow & use-after-free & double-free */
	char* tmp_user = (char *)(malloc(50*sizeof(char)));
	char* tmp_pass = (char *)(malloc(50*sizeof(char)));
	/* Uncomment the following line for stack-based buffer overflow */
	// char tmp_user[16], tmp_pass[16];
	if((username[0] >= 'A' && username[0] <= 'Z') && (username[1] >= '0' && username[1] <= '9'))
	{
		/* POTENTIAL FLAW: data may not have enough space to hold source */
		/* Uncomment the following line for heap-based & stack-based buffer overflow */	    
		// strcpy(tmp_user, username);
		/* POTENTIAL FLAW: data may not have enough space to hold source */
		/* Uncomment the following line for heap-based & stack-based buffer overflow */	    
		// strcpy(tmp_pass, password);
		if(!strcmp(tmp_user, def_user) && !strcmp(tmp_pass, def_pass)) 
		{	
			return true;
		}
		char passwd[50]; 
		int fd = open(tmp_user, O_RDONLY);
		if(fd < 0) 
		{ 
			printf("An unexpected problem occurred!\n"); 
			return false; 
		}
		read(fd, passwd, sizeof(passwd));
		if(!strcmp(passwd, tmp_pass)) 
		{ 
			return true; 
		}
	} 
	return false;
}
bool signin(char *username, char *password)
{
	if(check(username, password))
	{
		printf("Hey %s, you logged in successfully\n", username);
		/* Uncomment the following line for double-free & use-after-free) */
		free(username); free(password); 
		return true;
	} 
	else 
	{ 
		printf("The username or password is wrong\n"); 
		return false; 
	}
}
void authentication(char *username, char *password)
{
	/* Uncomment the following two lines for heap-based buffer overflow & use-after-free & double-free */
	char* tmp_user = (char *)(malloc(80*sizeof(char)));
	char* tmp_pass = (char *)(malloc(80*sizeof(char)));
	/* Uncomment the following line for stack-based buffer overflow */
	// char tmp_user[32], tmp_pass[32];
	/* POTENTIAL FLAW: data may not have enough space to hold source */
	/* Uncomment the following line for heap-based & stack-based buffer overflow */
	// memcpy(tmp_user, username, strlen(username));
	/* POTENTIAL FLAW: data may not have enough space to hold source */
	/* Uncomment the following line for heap-based & stack-based buffer overflow */
	// memcpy(tmp_pass, password, strlen(password));
	signin(tmp_user, tmp_pass);
	/* POTENTIAL FLAW: Use of data that may have been freed in line 63 */
	/* Uncomment the following line for use-after-free */
	// tmp_user[80-1] = '\0'; tmp_pass[80-1] = '\0';
	/* POTENTIAL FLAW: Free data here - line 63 frees data as well */
	/* Uncomment the following line for double-free */
	free(tmp_user);	free(tmp_pass);
}
int main (int argc, char *argv[])
{
	/* uncomment for stack-based buffer overflow */
	// char username[64]; char password[64];
	/* Uncomment the following two lines for heap-based buffer overflow & use-after-free & double-free */
	char *username = (char *)(malloc(100*(sizeof(char))));
	char *password = (char *)(malloc(100*(sizeof(char))));
	printf("Enter username :"); scanf("%s", username); 
	printf("Enter password :"); scanf("%s", password);
	if(argc >= 3) 
	{ 
		authentication(argv[1], argv[2]); 
	}
	else
	{
		if(username[0] >= 'A' && username[0] <= 'Z') 
		{ 
			signup(username, password); 
		}
		else 
		{ 
			printf("The selected username is not valid, it must start with an uppercase letter"); 
		}
	}
}
