typedef  char	Boolean,	*String;

typedef  union  _attribute_value
	 {
	    short	_discr_val;
	    float	_cont_val;
	 }
	 	AttValue, *Description; 

#define  CVal(Case,Attribute)   Case[Attribute]._cont_val
#define  DVal(Case,Attribute)   Case[Attribute]._discr_val
#define  Class(Case)			Case[MaxAtt+1]._discr_val

typedef  struct  _band
	{
		int		_continuous;
		int		_maxband;
		float*	_min;
		float*	_max;
	} BandInfo; 

typedef  struct  _candidate		/* one candidate item = one attribute range */
	{
	    int	_att;
		int	_val;
	} CandiItem; 

typedef  struct  _dist			/* deltaf value for one candidate*/
	{
		struct	_candidate _candiItem;
	    int	_weight;
		double	_CDF;
		Boolean _flag;
	} DistItem; 

typedef  struct  _treatment		/* one treatment item = one candidate set */
	{
		struct	_candidate *_candiSet;
		int		_num;
	    float	_worth_data;
		float	_worth_test;
	} TreatItem; 




