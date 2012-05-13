Hash Calculation Module
Sleuth Kit Framework C++ Module
April 2012


This module is for the C++ Sleuth Kit Framework. 


DESCRIPTION

This module is for a file analysis pipeline.  It calculates the MD5
and/or SHA1 hash of a given file and saves the result to the database.


USAGE

The initialize() method takes an argument to define what hash calculations
to perform.  If nothing is specified, both hash values are calculated.
Otherwise, itlooks for the string "MD5" or "SHA1" in the argument string.

Added from main_repo, 2.
