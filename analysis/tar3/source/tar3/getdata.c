/**********************************************/
/*								              */
/*	Get case descriptions from data file	  */
/*	--------------------------------------	  */
/*									          */
/**********************************************/

#include "defns.h"
#include "types.h"
#include "extern.h"

Description GetDescription();
Boolean ReadName();
int Which();
void Error();

/************************************************************************/
/*									                                    */
/*  Read raw case descriptions from file with given extension.		    */
/*									                                    */
/*  On completion, cases are stored in:									*/
/*  Item[0..MaxItem]	--	Data Description							*/
/*																		*/
/************************************************************************/

#define Inc 2048

void  GetData(Extension)
/*  --------  */
    String Extension;
{
    FILE *Df, *fopen();
    char Fn[100];
    long ItemSpace=0;
    Description Dvec;

    /*  Open data file  */

    strcpy(Fn, FileName);
    strcat(Fn, Extension);
    if ( ! ( Df = fopen(Fn, "r") ) ) Error(0, Fn, "");

	/*  Read items from data file  */

	ItemSpace = Inc;
	Item = (Description *)calloc(ItemSpace, sizeof(Description));

	MaxItem= -1;
	while ( (Dvec = GetDescription(Df)) != Nil)
	{
		if ( Class(Dvec) == Invalid )	continue;

		if ( ++MaxItem >= ItemSpace )
		{
			ItemSpace += Inc;
			Item = (Description *)realloc(Item, ItemSpace*sizeof(Description));
		}
		Item[MaxItem] = Dvec;

	}
	fclose(Df);
}
    

/********************************************************************/
/*																	*/
/*  Read a raw case description from file Df.						*/
/*																	*/
/*  For each attribute, read the attribute value from the file.		*/
/*  If it is a discrete valued attribute, find the associated no.	*/
/*																	*/
/*  Returns the Description of the case (i.e. the array of			*/
/*  attribute values).												*/
/*																	*/
/********************************************************************/


Description GetDescription(Df)
/*          ---------------  */
    FILE *Df;
{
    char name[500], *endname, buffer[200];
    int Dv,InNow,InChg,i,Maxband;
    float Cv;
	short Att;
    Description Dvec;

	/* Read in attribute values */
    
	Dvec = (Description) calloc(MaxAtt+2, sizeof(AttValue));
	Class(Dvec) = 0 ;
	ForEach(Att, 0, MaxAtt)
    {
		if ( !	ReadName(Df, name) ) return Nil;

		if ( Class(Dvec) == Invalid ) continue;

		if ( MaxAttVal[Att] )
		{
			/*  Discrete value  */ 

	        if ( ! ( strcmp(name, "?") ) )  Dv = Unknown;
			else
	        {
				/* accept those satisfy Now */

				InNow=InChg=1;

				if ( strcmp(AttValNow[Att][0],"true") && strcmp(AttValNow[Att][0],"ignore") )
					InNow = Which(name, AttValNow[Att], 0, MaxAttNow[Att]);

/*				if ( strcmp(AttValChg[Att][0],"true") && strcmp(AttValChg[Att][0],"ignore") )
					InChg = Which(name, AttValChg[Att], 0, MaxAttChg[Att]);*/

				if ( InNow < 0 && InChg < 0 )	
					Class(Dvec) = Invalid;
				
				if ( ! AttBand[Att]._continuous )
				{
					/* associate the discrete value with its no */
					Dv = Which(name, AttValName[Att], 0, MaxAttVal[Att]);
					if ( Dv < 0)	Error(4, AttName[Att], name);
				}
				else
				{
					/* read in .test data */
					/* associate the oringinal continuous value with its band no */
					Cv = (float) strtod(name, &endname);
					Maxband=AttBand[Att]._maxband;
					if ( Cv < AttBand[Att]._min[0] )
					{
						Dv=0;
						AttBand[Att]._min[0]=Cv;
						sprintf(buffer,"[%f..%f)",Cv,AttBand[Att]._max[0]); 
						strcpy(AttValName[Att][0],buffer);
					}
					else if ( Cv >= AttBand[Att]._max[Maxband] )
					{
						Dv=Maxband;
						Cv=(float)(Cv);	/* note: last band=[min,max] */
						AttBand[Att]._max[Maxband]=Cv;
						sprintf(buffer,"[%f..%f]",AttBand[Att]._min[Maxband],Cv); 
						strcpy(AttValName[Att][Maxband],buffer);
					}
					else
					{
						Dv=Unknown;
						ForEach(i, 0, Maxband)
						{
							/* note: each band=[min,max) except the last */
							if ( Cv >= AttBand[Att]._min[i] && Cv < AttBand[Att]._max[i] )
							{
								Dv=i;
								break;
							}
						}
						if ( Dv == Unknown )	Error(11, AttName[Att], name);
					}
				}
	        }

	        DVal(Dvec, Att) = Dv;
	    }
	    else
	    {
			/*  Continuous value  */

	        if ( ! ( strcmp(name, "?") ) )	Cv = Unknown;
	        else
			{
				Cv = (float) strtod(name, &endname);
				if ( endname == name || *endname != '\0' )	Error(4, AttName[Att], name);
			}
			
			CVal(Dvec, Att) = Cv;
	    }
	}

	/* Read in class values */

	ReadName(Df, name); 

	if (Class(Dvec) != Invalid)
	{
		if ( (Dv = Which(name, ClassName, 0, MaxClass)) < 0 )	Error(5, "", name);
		Class(Dvec) = Dv;
	}
	
    return Dvec;
}


/*************************************************************/
/*	                        								 */
/*	Locate value Val in List[First] to List[Last]			 */
/*							                        		 */
/*************************************************************/


int Which(Val, List, First, Last)
/*  -------------------------  */
    String Val, List[];
    short First, Last;
{
    short n=First;

    while ( n <= Last && strcmp(Val, List[n]) ) n++;

    return ( n <= Last ? n : First-1 );
}