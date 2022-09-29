/****************************************************/
/*													*/
/*		     Tar2  Randomized Version				*/
/*		  ---------------------------------			*/
/*		   Hu,Ying   ECE UBC	Dec,2001			*/
/*													*/
/*					huying_ca@yahoo.com				*/
/*													*/
/****************************************************/
#include "defns.h"
#include "types.h"
#include "global.h"


#define	Inc 1024

void ReadCfg();
void GetNames();
void GetData();
void Discretize();
float Worth();
void DeltaDist();
void DistDetail();
void Simulate();
void TestTreatment();
void Summary();

void GetTime(char* buffer)
{
   char dtbuff[80];
    time_t rawtime;
    struct tm *info;
   
   time( &rawtime );

   info = localtime( &rawtime );

   strftime(dtbuff,80,"%x - %I:%M%p", info);


   sprintf(buffer, "%s",dtbuff);

}


int main(int argc, char* argv[])
{
	int	i,Option; 
	time_t StarTime,SetupTime,ComputeTime,TesTime;
	TreatItem TmpTreat;
	char DateTime[50];
	Boolean CommandOk=true, DiscreArg = true;

	printf("-------------------------------------------------------------------");
	printf("\n                Welcome to TARZAN (Version 3.0)");
	printf("\n        Copyright (c) 2001 Tim Menzies (tim@menzies.com)");
	printf("\n              Copy policy: GPL-2 (see www.gnu.org)");
	printf("\n");
	printf("\n...while on high, our hero watches for the right chance to strike!");
	printf("\n-------------------------------------------------------------------\n");

	/* command line options */
	
	ReverseClass = false;
	Option = 3;

	if		( argc < 2 )	CommandOk = false;
	else if ( argc == 2 && argv[1][0] == '-' )	CommandOk = false;
	else if ( argc > 2 )
	{
		ForEach (i, 1, argc-2 )
		{
			if      ( !strcmp(argv[i], "-r") )	ReverseClass=true;
			else if ( !strcmp(argv[i], "-c") )	Option = 1;
			else if ( !strcmp(argv[i], "-d") )	Option = 2;
			else if ( !strcmp(argv[i], "-o") )	DiscreArg = false;
			else	CommandOk = false;
		}
	}

	if ( CommandOk )
		FileName = argv[argc-1];
	else
	{
		printf("\n Syntax: tar3 [-r] [-c] [-d] filestem");
		printf("\n Option: [-r] Reverse classes");
		printf("\n Option: [-c] Generate class distribution only");
		printf("\n Option: [-d] Generate confidence1 distribution only");
		printf("\n Option: [-o] Use Ying's old discretization");
		printf("\n Option: [-?] Command line help");
		printf("\nexample: tar3 c:\\tar3\\samples\\iris \n");
		exit(1);
	}

	/* get start time */

	time(&StarTime);
	
	/* initialize globles */
	
	MaxTreat = -1;
	TreatSetSpace = Inc;
	TreatSet = (TreatItem*) calloc(TreatSetSpace,sizeof(TreatItem));

	MaxFailedRx = -1;
	FailedRxSpace = Inc;
	FailedRx = (TreatItem*) calloc(FailedRxSpace,sizeof(TreatItem));

	/* data read in */
	
	GetNames();		/* must be read prior to .cfg */
	ReadCfg();
	GetData(".data");
	printf("\n\nRead %d cases (%d attributes) from %s.data\n",MaxItem+1,MaxAtt+1,FileName);

	/* raw data process */
	
	Discretize(DiscreArg);
	
	/* class distribution: baseline worth */
	TmpTreat._num = -1;
	Worth(TmpTreat, true);	
	MinWorth = 1;
	time(&SetupTime);

	/* confidence1 distribution*/
	if ( Option != 1 ) 	DeltaDist();	

	/* print out distribution details:
	   confidence1 values for attributes */
	if ( Option == 2 ) 	DistDetail();	

	/* get treatments */
	if ( Option == 3 )
	{
		Simulate();
		time(&ComputeTime);

		/* read in .test file */
		if ( ! strncmp(FileName,"XDF",3) )
		{
			free(Item);
			GetData(".test");
			printf("\nTreatment tested on %s.test (%d cases * %d attributes)\n"
			,FileName,MaxItem+1,MaxAtt+1);

			/* don not use Skew in xval trials for testing */
			Skew = 0;				
			Worth(TmpTreat, true);
		}
		
		/* test treatments learnt */
		TestTreatment();

		if ( ! strncmp(FileName,"XDF",3) )
			Summary(FileName);
	}
	time(&TesTime);

	/* print out runtime */
	GetTime(DateTime);
	printf("\n\n---- %s ---\n",DateTime);
	printf("   Setup: %ld sec\n",(SetupTime - StarTime));
	if ( Option == 3 )
	{
		printf(" Compute: %ld sec\n",(ComputeTime - SetupTime));
		printf("   Apply: %ld sec\n",(TesTime - ComputeTime));
	}
	printf("   Total: %ld sec\n",(TesTime - StarTime));
	printf("--------------------------\n");

	return 0;
}



