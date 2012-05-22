Hash Calculation Module
Sleuth Kit Framework C++ Module
May 2012


This module is for the C++ Sleuth Kit Framework.


MODULE DESCRIPTION

This module is a file analysis module that calculates hash values of the 
contents of a given file.

MODULE USAGE

Configure the file analysis pipeline to include this module by adding a 
"MODULE" element to the pipeline configuration file. Set the "arguments" 
attribute of the "MODULE" element to specify which hashes to calculate. 
Valid values are "MD5", "SHA1", or the empty string, which will result
in both hashes being calculated. Hash names can be in any order and 
may be separated by spaces or commas.