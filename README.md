# perl-pcapng

I intend to build a pure perl pcapng parser module that interacts with the pcapng format.

Currently the file parser has 2 modes:
Mode1 - Read Whole File
- You give the script a pcapng file location and it will open the whole file and read the entirety of the file.  It will return a hash or hashes with all of the sections broken out.

Mode2 - Read and Return Individual Blocks
- You give the script a file handle and location of where it is in the file, and it will only read a single block at a time. At the end of each block it will return a hash that has the contents of the block stored in the hash. 
