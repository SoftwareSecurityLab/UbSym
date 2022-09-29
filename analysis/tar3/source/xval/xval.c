/*****************************************************************/
/*																 */
/*		Program to perform the cross-validation	trials			 */
/*		-------------------------------------------------		 */
/*		invocation: xval filestem N								 */
/*****************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define	ForEach(var,F,L)	for(var=F; var<=L; ++var) 

void xvalPrep();
void xval();

void main(int argc, char *argv[])
/*  ----  */
{
	char Fn[30],Prog[100];
	int Splits;
	time_t ltime,etime;

	/* usage info*/
	if (argc != 4 )
	{
		printf("\nUsage Examples:");
		printf("\n---------------------------------------------------------");
		printf("\n(1)Perform xval preparation (data split) only\n");
		printf("\n    xval -p c:\\ying\\data\\iris 10\n");
		printf("\n(2)Perform xval with tar2 on iris.data\n");
		printf("\n    xval c:\\ying\\bin\\tar2.exe c:\\ying\\data\\iris 10\n");
		printf("\n(3)Perform xval with tar2r on iris.data\n");
		printf("\n    xval c:\\ying\\bin\\tar2r.exe c:\\ying\\data\\iris 10\n");
		printf("\n---------------------------------------------------------");
		printf("\n\n");
		exit(1);
	}

	sscanf(argv[argc-2], "%s", Fn);
    sscanf(argv[argc-1], "%d", &Splits);

	time(&ltime);

	xvalPrep(Fn, Splits);

	/* if invoke tar2 or tar2r */
	if ( strcmp(argv[1], "-p") ) 
	{
		strcpy(Prog, argv[1]);
		printf("\nPerform %d-way cross validation with %s on %s...\n\n",Splits,Prog,Fn);
		xval(Fn, Prog, Splits);
	}

	time(&etime);
	printf("\nRun time: %ld sec\n",(etime-ltime));
}


/*****************************************************************
																 
		invoke xvalPrep and program
		
*****************************************************************/

void xval(char *Fn, char* Program, int Splits)
{
	char command[100],suffix[5],OldName[20],NewName[20];
	int Loop;

	/* perform the cross-validation trials */

	strcpy(OldName, Fn);
	
	ForEach(Loop, 0, Splits-1)
	{
		sprintf(suffix,"%d",Loop);
		strcpy(NewName, "XDF");
		strcat(NewName, suffix);

		/* rename filestem.cfg XDF.cfg */
		strcpy(command, "rename ");
		strcat(command, OldName);
		strcat(command, ".cfg ");
		strcat(command, NewName);
		strcat(command, ".cfg");
		system(command);

		/* rename filestem.names XDF.names */
		strcpy(command, "rename ");
		strcat(command, OldName);
		strcat(command, ".names ");
		strcat(command, NewName);
		strcat(command, ".names");
		system(command);

		/* invoke program: "program filestem > filestem.out " */
		strcpy(command, Program);
		strcat(command, " ");
		strcat(command, NewName);
		strcat(command, " > ");
		strcat(command, NewName);
		strcat(command, ".out");
		/*printf("%s\n",command);*/
		system(command);

		/* update OldName*/
		strcpy(OldName, NewName);
	}

	/* rename back */
	strcpy(command, "rename ");
	strcat(command, OldName);
	strcat(command, ".cfg ");
	strcat(command, Fn);
	strcat(command, ".cfg");
	system(command);

	strcpy(command, "rename ");
	strcat(command, OldName);
	strcat(command, ".names ");
	strcat(command, Fn);
	strcat(command, ".names");
	system(command);

	/* delete XDF files*/
	strcpy(command, "del XDF*.data ");
	system(command);
	strcpy(command, "del XDF*.test ");
	system(command);

}