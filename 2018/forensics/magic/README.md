1. Concatenate all the files into one
2. the text is in base 64, decrypt it
3. the result is a gunzip file with a wrong header:
	the header has to starts with byte "50" but the file start with byte "51" change it.
4. Now you can decompress it, and again and again and again. To find out the type of compression used use "$ file myfile"

5. Tadaaaaa!
