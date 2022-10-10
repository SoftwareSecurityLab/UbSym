/************************************************************************/
/*																		*/
/*	Program to prepare data file for cross-validation					*/
/*	-------------------------------------------------					*/
/*																		*/
/*	- If only filestem is given, add .data as default extension			*/
/*	- Data are divided into N blocks, with class distributions			*/
/*    as uniform as possible in	each block.								*/
/*	- On completion, generate XDF[0..N-1].data and XDF[0..N-1].test		*/
/*																		*/
/************************************************************************/


#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define	ForEach(var,F,L)	for(var=F; var<=L; ++var) 
#define MAXLINE 5000		/* maximum line length */

void xvalPrep(char* F, int Splits)
/*  ----  */
{
	FILE	*NfData,*NfTest;
	FILE	*Nf, *fopen();
	char	**Item,**Case;
	int		ItemSpace=1000, MaxItem=0, MaxCase;
    int		i, First=0, Last, Length;
	int		*block, count, s1, s2 ;
    char	Line[MAXLINE], **ClassPtr, *Temp, *BeginClass();
	char	Fn[20],Fdata[20],Ftest[20],suffix[5];


	/* if only the file stem is given, add .data as default */

	strcpy(Fn,F);
	if ( strchr(Fn,'.') == NULL )
		strcat(Fn, ".data");
    
	if ( ! ( Nf = fopen(Fn, "r") ) ) 
	{
		printf("\nCan't open file %s\n",Fn);
		exit(1);
	}

	/* read in items*/

	printf("Read and split from %s...\n",Fn);
    
    Item = (char **) malloc(ItemSpace * sizeof(char *));
    while ( fgets(Line, MAXLINE, Nf) )
    {
		if ( MaxItem >= ItemSpace )
		{
			ItemSpace += 1000;
			Item = (char **) realloc(Item, ItemSpace * sizeof(char *));
		}
		Length = strlen(Line)+2;
		Item[MaxItem] = (char *) malloc(Length);
		memcpy(Item[MaxItem], Line, Length);
		MaxItem++;
    }
    if ( ! MaxItem-- ) exit(1);

    /*  Find classes  */

    ClassPtr = (char **) malloc((MaxItem+1) * sizeof(char *));
    ForEach(i, 0, MaxItem)
    {
		ClassPtr[i] = BeginClass(Item[i]);
    }

    /*  Sort by class  */

    fprintf(stderr, "\nClass frequencies:\n");
    while ( First <= MaxItem )
    {
		Last = First;

		ForEach(i, First+1, MaxItem)
		{
			if ( ! strcmp(ClassPtr[i], ClassPtr[First]) )
			{
				Last++;
				Temp = Item[Last];
				Item[Last] = Item[i];
				Item[i] = Temp;

				Temp = ClassPtr[Last];
				ClassPtr[Last] = ClassPtr[i];
				ClassPtr[i] = Temp;
			}
		}
		fprintf(stderr, "%6d class %s\n", Last-First+1, ClassPtr[First]);

		First = Last+1;
    }

	/* divide into N blockes, N=Splits, stored in Case[] */

	Case = (char **) malloc((MaxItem+1) * sizeof(char *));
	block = (int *) malloc(Splits * sizeof(int));

	MaxCase = -1;
    ForEach(First, 0, Splits-1)
    {
		count=0;
		for ( i = First ; i <= MaxItem ; i += Splits )
		{
			MaxCase++;
			count++;

			Length = strlen(Item[i])+2;
			Case[MaxCase] = (char *) malloc(Length);
			strcpy(Case[MaxCase],Item[i]);
		}
		block[First]=count;
    }
	if ( MaxCase != MaxItem ) exit(1);

	/* generate N data files */

	ForEach(First, 0, Splits-1)
	{
		sprintf(suffix,"%d",First);
		strcpy(Fdata,"XDF");
		strcpy(Ftest,"XDF");
		strcat(Fdata,suffix);
		strcat(Ftest,suffix);
		strcat(Fdata,".data");
		strcat(Ftest,".test");
		
		NfData = fopen( Fdata, "w" );
		NfTest = fopen( Ftest, "w" );

		if (First ==0 )		s1 = 0;
		else				s1 += block[First-1];

		s2 = s1 + block[First] - 1;

		ForEach(i, 0, MaxCase )
		{
			if ( i >= s1 && i<= s2 )
			{
				fprintf(NfTest, "%s\n", Case[i]);
			}
			else
			{
				fprintf(NfData, "%s\n", Case[i]);
			}
		}
		fclose( NfData );
		fclose( NfTest );
	}
}


/*************************************************************/
/*															 */
/*	Find the beginning character of a class name			 */
/*															 */
/*************************************************************/

#define	dig(x)	(x >= '0' && x <= '9')

char *BeginClass(S)
/*    ----------  */
    char *S;
{
    char *F;

    F = S - 1;
    do
    {
		S = F + 1;
		while ( *S == ' ' || *S == '\t' || *S == '\n' ) S++;
		F = S;
		while ( *F != ',' && (*F != '.' || dig(*(F+1))) && *F != '\n' ) F++;
    } while ( *F == ',' );

    if ( *F != '.' ) *F = '.';
    *(F+1) = '\0';

    return S;
}