Hash Calculation Module
Sleuth Kit Framework C++ Module
May 2012


This module is for the C++ Sleuth Kit Framework.


DESCRIPTION

This module is a file analysis module that calculates 
hash values of file content.

USAGE

Configure the file analysis pipeline to include this module.

This module takes arguments to determine which hashes to calculate. 
Valid values are "MD5", "SHA1" or the empty string which will result
in both hashes being calculated. Hash names can be in any order and 
may be separated by spaces or commas. 
