#!/bin/bash

cp CWE122_Heap_Based_Buffer_Overflow/includes/std_testcase.h CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_strcpy
cp CWE122_Heap_Based_Buffer_Overflow/includes/std_testcase_io.h CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_strcpy
cp CWE122_Heap_Based_Buffer_Overflow/includes/testcases.h CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_strcpy

k=1
for ((i = 1; i <= 44; i++ ));
do
	FILE="CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_strcpy/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_$(printf "%02d" $i).c"
	if [ -f $FILE ]; then
		gcc $FILE CWE122_Heap_Based_Buffer_Overflow/includes/io.c -o $k
		k=$((k+1))
	fi
done
gcc CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_strcpy/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67a.c CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_strcpy/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67b.c CWE122_Heap_Based_Buffer_Overflow/includes/io.c -o $k

k=$((k+1))

rm CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_strcpy/std_testcase.h
rm CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_strcpy/std_testcase_io.h
rm CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_strcpy/testcases.h 

cp CWE122_Heap_Based_Buffer_Overflow/includes/std_testcase.h CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy
cp CWE122_Heap_Based_Buffer_Overflow/includes/std_testcase_io.h CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy
cp CWE122_Heap_Based_Buffer_Overflow/includes/testcases.h CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy

for ((i = 1; i <= 45; i++ ));
do
        FILE="CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE CWE122_Heap_Based_Buffer_Overflow/includes/io.c -o $k
                k=$((k+1))
        fi
done

gcc CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_67a.c CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_67b.c CWE122_Heap_Based_Buffer_Overflow/includes/io.c -o $k

k=$((k+1))

rm CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy/std_testcase.h
rm CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy/std_testcase_io.h
rm CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy/testcases.h

cp CWE122_Heap_Based_Buffer_Overflow/includes/std_testcase.h CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove
cp CWE122_Heap_Based_Buffer_Overflow/includes/std_testcase_io.h CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove
cp CWE122_Heap_Based_Buffer_Overflow/includes/testcases.h CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove

for ((i = 1; i <= 45; i++ ));
do
        FILE="CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE CWE122_Heap_Based_Buffer_Overflow/includes/io.c -o $k
                k=$((k+1))
        fi
done

gcc CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67a.c CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_67b.c CWE122_Heap_Based_Buffer_Overflow/includes/io.c -o $k

k=$((k+1))

rm CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove/std_testcase.h
rm CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove/std_testcase_io.h
rm CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove/testcases.h

cp CWE122_Heap_Based_Buffer_Overflow/includes/std_testcase.h CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memcpy
cp CWE122_Heap_Based_Buffer_Overflow/includes/std_testcase_io.h CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memcpy
cp CWE122_Heap_Based_Buffer_Overflow/includes/testcases.h CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memcpy

for ((i = 1; i <= 45; i++ ));
do
        FILE="CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memcpy/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memcpy_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE CWE122_Heap_Based_Buffer_Overflow/includes/io.c -o $k
                k=$((k+1))
        fi
done

rm CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memcpy/std_testcase.h
rm CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memcpy/std_testcase_io.h
rm CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memcpy/testcases.h

cp CWE122_Heap_Based_Buffer_Overflow/includes/std_testcase.h CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove
cp CWE122_Heap_Based_Buffer_Overflow/includes/std_testcase_io.h CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove
cp CWE122_Heap_Based_Buffer_Overflow/includes/testcases.h CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove

for ((i = 1; i <= 45; i++ ));
do
        FILE="CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE CWE122_Heap_Based_Buffer_Overflow/includes/io.c -o $k
                k=$((k+1))
        fi
done

rm CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove/std_testcase.h
rm CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove/std_testcase_io.h
rm CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove/testcases.h

cp CWE122_Heap_Based_Buffer_Overflow/includes/std_testcase.h CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_dest_char_strcat
cp CWE122_Heap_Based_Buffer_Overflow/includes/std_testcase_io.h CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_dest_char_strcat
cp CWE122_Heap_Based_Buffer_Overflow/includes/testcases.h CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_dest_char_strcat

for ((i = 1; i <= 44; i++ ));
do
        FILE="CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_dest_char_strcat/CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE CWE122_Heap_Based_Buffer_Overflow/includes/io.c -o $k
                k=$((k+1))
        fi
done

gcc CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_dest_char_strcat/CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67a.c CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_dest_char_strcat/CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67b.c CWE122_Heap_Based_Buffer_Overflow/includes/io.c -o $k

k=$((k+1))

rm CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_dest_char_strcat/std_testcase.h
rm CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_dest_char_strcat/std_testcase_io.h
rm CWE122_Heap_Based_Buffer_Overflow/CWE122_Heap_Based_Buffer_Overflow__c_dest_char_strcat/testcases.h
##################################################################################################################################

cp CWE415_Double_Free/includes/std_testcase.h CWE415_Double_Free/CWE415_Double_Free__malloc_free_int
cp CWE415_Double_Free/includes/std_testcase_io.h CWE415_Double_Free/CWE415_Double_Free__malloc_free_int

for ((i = 1; i <= 44; i++ ));
do
        FILE="CWE415_Double_Free/CWE415_Double_Free__malloc_free_int/CWE415_Double_Free__malloc_free_int_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE CWE415_Double_Free/includes/io.c -o $k
                k=$((k+1))
        fi
done

rm CWE415_Double_Free/CWE415_Double_Free__malloc_free_int/std_testcase.h
rm CWE415_Double_Free/CWE415_Double_Free__malloc_free_int/std_testcase_io.h

cp CWE415_Double_Free/includes/std_testcase.h CWE415_Double_Free/CWE415_Double_Free__malloc_free_long
cp CWE415_Double_Free/includes/std_testcase_io.h CWE415_Double_Free/CWE415_Double_Free__malloc_free_long

for ((i = 1; i <= 44; i++ ));
do
        FILE="CWE415_Double_Free/CWE415_Double_Free__malloc_free_long/CWE415_Double_Free__malloc_free_long_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE CWE415_Double_Free/includes/io.c -o $k
                k=$((k+1))
        fi
done

rm CWE415_Double_Free/CWE415_Double_Free__malloc_free_long/std_testcase.h
rm CWE415_Double_Free/CWE415_Double_Free__malloc_free_long/std_testcase_io.h

cp CWE415_Double_Free/includes/std_testcase.h CWE415_Double_Free/CWE415_Double_Free__malloc_free_int64_t
cp CWE415_Double_Free/includes/std_testcase_io.h CWE415_Double_Free/CWE415_Double_Free__malloc_free_int64_t

for ((i = 1; i <= 44; i++ ));
do
        FILE="CWE415_Double_Free/CWE415_Double_Free__malloc_free_int64_t/CWE415_Double_Free__malloc_free_int64_t_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE CWE415_Double_Free/includes/io.c -o $k
                k=$((k+1))
        fi
done

rm CWE415_Double_Free/CWE415_Double_Free__malloc_free_int64_t/std_testcase.h
rm CWE415_Double_Free/CWE415_Double_Free__malloc_free_int64_t/std_testcase_io.h

cp CWE415_Double_Free/includes/std_testcase.h CWE415_Double_Free/CWE415_Double_Free__malloc_free_struct
cp CWE415_Double_Free/includes/std_testcase_io.h CWE415_Double_Free/CWE415_Double_Free__malloc_free_struct

for ((i = 1; i <= 44; i++ ));
do
        FILE="CWE415_Double_Free/CWE415_Double_Free__malloc_free_struct/CWE415_Double_Free__malloc_free_struct_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE CWE415_Double_Free/includes/io.c -o $k
                k=$((k+1))
        fi
done

rm CWE415_Double_Free/CWE415_Double_Free__malloc_free_struct/std_testcase.h
rm CWE415_Double_Free/CWE415_Double_Free__malloc_free_struct/std_testcase_io.h

cp CWE415_Double_Free/includes/std_testcase.h CWE415_Double_Free/CWE415_Double_Free__malloc_free_wchar_t
cp CWE415_Double_Free/includes/std_testcase_io.h CWE415_Double_Free/CWE415_Double_Free__malloc_free_wchar_t

for ((i = 1; i <= 44; i++ ));
do
        FILE="CWE415_Double_Free/CWE415_Double_Free__malloc_free_wchar_t/CWE415_Double_Free__malloc_free_wchar_t_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE CWE415_Double_Free/includes/io.c -o $k
                k=$((k+1))
        fi
done

rm CWE415_Double_Free/CWE415_Double_Free__malloc_free_wchar_t/std_testcase.h
rm CWE415_Double_Free/CWE415_Double_Free__malloc_free_wchar_t/std_testcase_io.h
##################################################################################################################################

cp CWE121_Stack_Based_Buffer_Overflow/includes/std_testcase.h CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_strcpy
cp CWE121_Stack_Based_Buffer_Overflow/includes/std_testcase_io.h CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_strcpy
cp CWE121_Stack_Based_Buffer_Overflow/includes/testcases.h CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_strcpy

for ((i = 1; i <= 44; i++ ));
do
        FILE="CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_strcpy/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE CWE121_Stack_Based_Buffer_Overflow/includes/io.c -o $k
                k=$((k+1))
        fi
done
gcc CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_strcpy/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_67a.c CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_strcpy/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_67b.c CWE121_Stack_Based_Buffer_Overflow/includes/io.c -o $k

k=$((k+1))

rm CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_strcpy/std_testcase.h
rm CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_strcpy/std_testcase_io.h
rm CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_strcpy/testcases.h

cp CWE121_Stack_Based_Buffer_Overflow/includes/std_testcase.h CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_strcat
cp CWE121_Stack_Based_Buffer_Overflow/includes/std_testcase_io.h CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_strcat
cp CWE121_Stack_Based_Buffer_Overflow/includes/testcases.h CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_strcat

for ((i = 1; i <= 44; i++ ));
do
        FILE="CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_strcat/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cat_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE CWE121_Stack_Based_Buffer_Overflow/includes/io.c -o $k
                k=$((k+1))
        fi
done
gcc CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_strcat/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cat_67a.c CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_strcat/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cat_67b.c CWE121_Stack_Based_Buffer_Overflow/includes/io.c -o $k

k=$((k+1))

rm CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_strcat/std_testcase.h
rm CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_strcat/std_testcase_io.h
rm CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_strcat/testcases.h

cp CWE121_Stack_Based_Buffer_Overflow/includes/std_testcase.h CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memcpy
cp CWE121_Stack_Based_Buffer_Overflow/includes/std_testcase_io.h CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memcpy
cp CWE121_Stack_Based_Buffer_Overflow/includes/testcases.h CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memcpy

for ((i = 1; i <= 44; i++ ));
do
        FILE="CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memcpy/CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memcpy_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE CWE121_Stack_Based_Buffer_Overflow/includes/io.c -o $k
                k=$((k+1))
        fi
done

rm CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memcpy/std_testcase.h
rm CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memcpy/std_testcase_io.h
rm CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memcpy/testcases.h

cp CWE121_Stack_Based_Buffer_Overflow/includes/std_testcase.h CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove
cp CWE121_Stack_Based_Buffer_Overflow/includes/std_testcase_io.h CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove
cp CWE121_Stack_Based_Buffer_Overflow/includes/testcases.h CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove

for ((i = 1; i <= 44; i++ ));
do
        FILE="CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove/CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE CWE121_Stack_Based_Buffer_Overflow/includes/io.c -o $k
                k=$((k+1))
        fi
done

rm CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove/std_testcase.h
rm CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove/std_testcase_io.h
rm CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove/testcases.h

cp CWE121_Stack_Based_Buffer_Overflow/includes/std_testcase.h CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy
cp CWE121_Stack_Based_Buffer_Overflow/includes/std_testcase_io.h CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy
cp CWE121_Stack_Based_Buffer_Overflow/includes/testcases.h CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy

for ((i = 1; i <= 44; i++ ));
do
        FILE="CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE CWE121_Stack_Based_Buffer_Overflow/includes/io.c -o $k
                k=$((k+1))
        fi
done
gcc CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy_67a.c CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy_67b.c CWE121_Stack_Based_Buffer_Overflow/includes/io.c -o $k

k=$((k+1))

rm CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy/std_testcase.h
rm CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy/std_testcase_io.h
rm CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy/testcases.h

cp CWE121_Stack_Based_Buffer_Overflow/includes/std_testcase.h CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove
cp CWE121_Stack_Based_Buffer_Overflow/includes/std_testcase_io.h CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove
cp CWE121_Stack_Based_Buffer_Overflow/includes/testcases.h CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove

for ((i = 1; i <= 44; i++ ));
do
        FILE="CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE CWE121_Stack_Based_Buffer_Overflow/includes/io.c -o $k
                k=$((k+1))
        fi
done
gcc CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove_67a.c CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove_67b.c CWE121_Stack_Based_Buffer_Overflow/includes/io.c -o $k

k=$((k+1))

rm CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove/std_testcase.h
rm CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove/std_testcase_io.h
##################################################################################################################################

cp CWE416_Use_After_Free/includes/std_testcase.h CWE416_Use_After_Free/CWE416_Use_After_Free__malloc_free_char
cp CWE416_Use_After_Free/includes/std_testcase_io.h CWE416_Use_After_Free/CWE416_Use_After_Free__malloc_free_char

for ((i = 1; i <= 44; i++ ));
do
        FILE="CWE416_Use_After_Free/CWE416_Use_After_Free__malloc_free_char/CWE416_Use_After_Free__malloc_free_char_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE CWE416_Use_After_Free/includes/io.c -o $k
                k=$((k+1))
        fi
done

rm CWE416_Use_After_Free/CWE416_Use_After_Free__malloc_free_char/std_testcase.h
rm CWE416_Use_After_Free/CWE416_Use_After_Free__malloc_free_char/std_testcase_io.h

cp CWE416_Use_After_Free/includes/std_testcase.h CWE416_Use_After_Free/CWE416_Use_After_Free__malloc_free_long
cp CWE416_Use_After_Free/includes/std_testcase_io.h CWE416_Use_After_Free/CWE416_Use_After_Free__malloc_free_long

for ((i = 1; i <= 44; i++ ));
do
        FILE="CWE416_Use_After_Free/CWE416_Use_After_Free__malloc_free_long/CWE416_Use_After_Free__malloc_free_long_$(printf "%02d" $i).c"
        if [ -f $FILE ]; then
                gcc $FILE CWE416_Use_After_Free/includes/io.c -o $k
                k=$((k+1))
        fi
done

rm CWE416_Use_After_Free/CWE416_Use_After_Free__malloc_free_long/std_testcase.h
rm CWE416_Use_After_Free/CWE416_Use_After_Free__malloc_free_long/std_testcase_io.h

