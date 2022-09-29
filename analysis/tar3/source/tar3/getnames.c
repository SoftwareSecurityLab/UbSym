/*****************************************************************/
/*								                             	 */
/*	Get names of classes, attributes and attribute values		 */
/*	-----------------------------------------------------		 */
/*								                               	 */
/*****************************************************************/

#include "defns.h"
#include "types.h"
#include "extern.h"

#define  Space(s)	(s == ' ' || s == '\n' || s == '\t')
#define  SkipComment	while ( ( c = getc(f) ) != '\n' )

char	Delimiter;

void	GetConstraints();
void	Error();
String	CopyString();

/*************************************************************************/
/*                                  									 */
/*  Read a name from file f into string s, setting Delimiter.		     */
/*									                                     */
/*  - Embedded periods are permitted, but periods followed by space	     */
/*    characters act as delimiters.					                     */
/*  - Embedded spaces are permitted, but multiple spaces are replaced	 */
/*    by a single space.						                         */
/*  - Any character can be escaped by '\'.				                 */
/*  - The remainder of a line following '|' is ignored.			         */
/*									                                     */
/*************************************************************************/


Boolean ReadName(f, s)
/* --------------  */
    FILE *f;
    String s;
{
    register char *Sp=s;
    register int c;

    /*  Skip to first non-space character  */

    while ( ( c = getc(f) ) == '|' || Space(c) )
    {
		if ( c == '|' ) SkipComment;
    }

    /*  Return false if no names to read  */

    if ( c == EOF )
    {
		Delimiter = EOF;
		return false;  
    }

    /*  Read in characters up to the next delimiter  */

    while ( c != ':' && c != ',' && c != '\n' && c != '|' && c != EOF )
    {
		if ( c == '.' )
		{
			if ( ( c = getc(f) ) == '|' || Space(c) ) break;
			*Sp++ = '.';
		}

		if ( c == '\\' )
		{
			c = getc(f);
		}

		*Sp++ = c;

		if ( c == ' ' )
		{
			while ( ( c = getc(f) ) == ' ' )
				;
		}
		else
		{
			c = getc(f);
		}
    }

    if ( c == '|' ) SkipComment;
    Delimiter = c;

    /*  Strip trailing spaces  */

    while ( Space(*(Sp-1)) ) Sp--;

    *Sp++ = '\0';
    return true;
}


/*************************************************************************/
/*	                                    								 */
/*  Read the names of classes, attributes and legal attribute values.	 */
/*  On completion, these names are stored in:           				 */
/*		ClassName[0..MaxClass]	-  class names  	                     */
/*		AttName[0..MaxAtt]		-  attribute names	                     */
/*		MaxAttVal[a]	-	number of values for attribute a			 */
/*		AttValName[a][1..MaxAttVal[a]]	-  attribute value names		 */
/*									                                     */
/*************************************************************************/


void GetNames()
/*  ---------  */
{
    FILE *Nf, *fopen();
    char Fn[100], Buffer[1000], TmpClass[100];
    int AttCeiling=100, ClassCeiling=50, ValCeiling=100,i ;

    /*  Open names file  */

    strcpy(Fn, FileName);
    strcat(Fn, ".names");
    if ( ! ( Nf = fopen(Fn, "r") ) ) Error(0, Fn, "");

    /*  Get class names from names file  */

    ClassName = (String *) calloc(ClassCeiling, sizeof(String));
    MaxClass = -1;
    do
    {
		ReadName(Nf, Buffer);
		if ( ++MaxClass >= ClassCeiling)
		{
			ClassCeiling += 50;
			ClassName = (String *) realloc(ClassName, ClassCeiling*sizeof(String));
		}
		ClassName[MaxClass] = CopyString(Buffer);
    }
    while ( Delimiter == ',' );

	if ( ReverseClass ) 
	{
		ForEach (i,0,MaxClass/2)
		{
			strcpy(TmpClass,ClassName[i]);
			strcpy(ClassName[i],ClassName[MaxClass-i]);
			strcpy(ClassName[MaxClass-i],TmpClass);
		}
	}

    /*  Get attribute and attribute value names from names file  */

    AttName = (String *) calloc(AttCeiling, sizeof(String));
    MaxAttVal = (short *) calloc(AttCeiling, sizeof(short));
    AttValName = (String **) calloc(AttCeiling, sizeof(String *));
	AttBand = (BandInfo *) calloc(AttCeiling,sizeof(BandInfo));
    
    MaxAtt = -1;
	while ( ReadName(Nf, Buffer) && strcmp(Buffer,"NOW") && strcmp(Buffer,"CHANGES"))
    {
		/* get attribute name */
	
		if ( Delimiter != ':' ) Error(1, Buffer, "");

		if ( ++MaxAtt >= AttCeiling )
		{
			AttCeiling += 100;
			AttName = (String *) realloc(AttName, AttCeiling*sizeof(String));
			MaxAttVal = (short *) realloc(MaxAttVal, AttCeiling*sizeof(short));
			AttValName = (String **) realloc(AttValName, AttCeiling*sizeof(String *));
			AttBand = (BandInfo *) realloc(AttBand, AttCeiling*sizeof(BandInfo));
		}

		AttName[MaxAtt] = CopyString(Buffer);	/*attribut name*/
	
		/* get attribute value name */

		MaxAttVal[MaxAtt] = -1;
		AttValName[MaxAtt] = (String *) calloc(ValCeiling, sizeof(String));
		do
		{
			if ( ! ( ReadName(Nf, Buffer) ) ) Error(2, AttName[MaxAtt], "");

			if ( ++MaxAttVal[MaxAtt] >= ValCeiling )
			{
				ValCeiling += 100;
				AttValName[MaxAtt] = 
					(String *) realloc(AttValName[MaxAtt], ValCeiling*sizeof(String));
			}
			AttValName[MaxAtt][MaxAttVal[MaxAtt]] = CopyString(Buffer);

		}
		while ( Delimiter == ',' );

		/*  Cannot have only one discrete value for an attribute  */

		if ( MaxAttVal[MaxAtt] == 0 )
		{
			AttBand[MaxAtt]._continuous=true;
			if ( strcmp(Buffer,"continuous") )	Error(3, AttName[MaxAtt], "");
		}
		else
		{
			AttBand[MaxAtt]._continuous=false;
		}

    }
	
	GetConstraints(Nf, Buffer);
    fclose(Nf);
}


/*************************************************************************/
/*	                                    								 */
/*  Read in constraints,												 */
/*	NOW																	 */
/*	CHANGES																 */
/*									                                     */
/*************************************************************************/

void GetConstraints(Nf, Identifier)
FILE *Nf;
char Identifier[1000];
{
    char Buffer[1000];
	int i;

	/* process NOW: read in and throw away */

	MaxAttNow = (short *) calloc(MaxAtt+1, sizeof(short));
	AttValNow = (String **) calloc(MaxAtt+1, sizeof(String *));
	if ( ! strcmp(Identifier,"NOW") )
	{
		/* Now ranges exist */
		if ( ReadName(Nf, Buffer) && Delimiter == ':' )
		{
			ForEach(i, 0, MaxAtt)
			{
				if ( strcmp(Buffer,AttName[i]) )	Error(9, AttName[i], "");
				AttValNow[i] = (String *) calloc(MaxAttVal[i]+1, sizeof(String));
				MaxAttNow[i] = -1;
				do
				{
					ReadName(Nf, Buffer);
					AttValNow[i][++MaxAttNow[i]] = CopyString(Buffer);
				}
				while (Delimiter == ',');

				ReadName(Nf, Buffer);	
			}
			printf("\nNOW: specified");
		}
		strcpy(Identifier, Buffer);
	}
	else
	{
		/* no Now ranges -- set to default */
		ForEach(i, 0, MaxAtt)
		{
			MaxAttNow[i]=0;
			AttValNow[i] = (String *) calloc(MaxAttVal[i]+1, sizeof(String));
			AttValNow[i][0] = "true";
		}
		printf("\ndefault: NOW=true");
	}

	/* process CHANGES: read in and store it */

	MaxAttChg = (short *) calloc(MaxAtt+1, sizeof(short));
	AttValChg = (String **) calloc(MaxAtt+1, sizeof(String *));
	if (! strcmp(Identifier,"CHANGES"))
	{
		/* Changes exist */
		if ( ReadName(Nf, Buffer) && Delimiter == ':' )
		{
			ForEach(i, 0, MaxAtt)
			{
				if ( strcmp(Buffer,AttName[i]) )	Error(10, AttName[i], "");
				AttValChg[i] = (String *) calloc(MaxAttVal[i]+1, sizeof(String));
				MaxAttChg[i] = -1;
				do
				{
					ReadName(Nf, Buffer);
					AttValChg[i][++MaxAttChg[i]] = CopyString(Buffer);
				}
				while (Delimiter == ',');

				ReadName(Nf, Buffer);	
			}
			printf("\nCHANGES: specified");
		}
		strcpy(Identifier, Buffer);
	}
	else
	{
		/* no Changes -- set to default */
		ForEach(i, 0, MaxAtt)
		{
			MaxAttChg[i]=0;
			AttValChg[i] = (String *) calloc(MaxAttVal[i]+1, sizeof(String));
			AttValChg[i][0] = "true";
		}
		printf("\ndefault: CHANGES=true");
	}
}


/************************************************************************/
/*									                                    */
/*  Read parameters from .cfg file.									    */
/*									                                    */
/*  On completion, parameters are stored in global valuables.			*/
/*																		*/
/************************************************************************/

void  ReadCfg()
/*  --------  */
{
    FILE *Nf, *fopen();
    char Fn[100],Buffer[500],*ParaName,*ParaVal;

    /*  Open cfg file  */

    strcpy(Fn, FileName);
    strcat(Fn, ".cfg");
    if ( ! ( Nf = fopen(Fn, "r") ) ) Error(0, Fn, "");

	/* set to default */
	Granularity = 3;
	Step = 2;
	MaxTreatNum = 30;
	MinTreatSize = 1;
	MaxTreatSize = 5;
	FutileTrials = 5;
	RandomTrials = 1;
	Skew = 0.5;

    while ( ReadName(Nf, Buffer) )
    {
		if ( Delimiter != ':' ) Error(6, Buffer, "");
		ParaName = CopyString(Buffer);	/* parameter name*/
	
		if ( ! ( ReadName(Nf, Buffer) ) ) Error(7, ParaName, "");
		ParaVal = CopyString(Buffer);	/* parameter value*/

		if ( ! strcmp(ParaName, "granularity") )	
			Granularity = atoi(ParaVal);
		else if ( ! strcmp(ParaName, "step") )	
			Step = (float)atof(ParaVal);
		else if ( ! strcmp(ParaName, "maxNumber") )
			MaxTreatNum = atoi(ParaVal);
		else if ( ! strcmp(ParaName, "minSize") )	
			MinTreatSize = atoi(ParaVal);
		else if ( ! strcmp(ParaName, "maxSize") )	
		{
			MaxTreatSize = atoi(ParaVal);
			if ( MaxTreatSize > MaxAtt+1 )	/* NOTE: requires .names be read in before .cfg */
											/* different from TAR2.2 */
			{
				MaxTreatSize = MaxAtt+1;
				printf("\nWarning! Max treatment size must <= total attributes! Reset to %d\n", 
					MaxTreatSize);
			}
		}
		else if ( ! strcmp(ParaName, "futileTrials") )
			FutileTrials=atoi(ParaVal);
		else if ( ! strcmp(ParaName, "randomTrials") )	
			RandomTrials=atoi(ParaVal);
		else if (! strcmp(ParaName, "bestClass"))
		{
			Skew=(float)atof(ParaVal)/100;
			if ( Skew <= 0 || Skew > 1 )
			{
				Skew = 0.5;
				printf("\nWarning! bestClass means what proportion of best class examples should be remained after applying a treatment. Default=50%");
			}
		}
		else
	    	Error(8, ParaName, "");
    }	

	/* print out config parameters*/
	printf("\nConfig: granularity  %d", Granularity);
	printf("\n        maxNumber    %d", MaxTreatNum);
	printf("\n        minSize      %d", MinTreatSize);
	printf("\n        maxSize      %d", MaxTreatSize);
	printf("\n        randomTrials %d", RandomTrials);
	printf("\n        futileTrials %d", FutileTrials);
	printf("\n        bestClass    %5.2f%%\n",Skew*100);

    fclose(Nf);
}


/*********************************************************/
/*									                     */
/*	Allocate space then copy string into it				 */
/*									                     */
/*********************************************************/

String CopyString(x)
/* -----------  */
    String x;
{
    char *s;

    s = (char *) calloc(strlen(x)+1, sizeof(char));
    strcpy(s, x);
    return s;
}


/*************************************/
/*									 */
/*		Error messages				 */
/*									 */
/*************************************/

void Error(n, s1, s2)

/*  -----  */
    short n;
    String s1, s2;
{
    static char Messages=0;

    printf("%s,%s",s1,s2);
    printf("\nERROR:  ");
    switch(n)
    {
	case 0: printf("cannot open file %s%s\n", s1, s2);
		exit(1);

	case 1:	printf("colon expected after attribute name %s\n", s1);
		break;

	case 2:	printf("unexpected eof while reading attribute %s\n", s1);
		break;

	case 3: printf("attribute %s has only one value\n", s1);
		break;

	case 4: printf("case %d's value of '%s' for attribute %s is illegal\n",
		    MaxItem+1, s2, s1);
		break;

	case 5: printf("case %d's class of '%s' is illegal\n", MaxItem+1, s2);
		break;

	case 6:	printf("colon expected after parameter name %s\n", s1);
		break;

	case 7:	printf("unexpected eof while reading parameter %s value\n", s1);
		break;

	case 8:	printf("illegal parameter name %s\n", s1);
		break;

	case 9: printf("attribute name [%s] doesn't match when reading NOW\n",s1);
		break;

	case 10: printf("attribute name [%s] doesn't match when reading CHANGES\n",s1);
		break;

	case 11: printf("can't locate discretized value for attribute[%s]=%s\n",s1,s2);
		break;

    }

	exit(1);
}
