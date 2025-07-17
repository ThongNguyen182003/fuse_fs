/**
 * @file fuse_main.c
 * @brief Entry point for the custom FUSE filesystem.
 * 
 * This file defines the FUSE operations to be used and starts the FUSE main loop.
 */

#include "fuse_core.h"

/// Define the FUSE operations to be used by the filesystem
static struct fuse_operations my_oper = {
    .getattr = my_getattr,   ///< Handle file attribute queries
    .open = my_open,         ///< Handle file open
    .read = my_read,         ///< Handle file read (with AES decryption and whitelist check)
    .write = my_write,       ///< Handle file write (with AES encryption and whitelist check)
    .readdir = my_readdir,   ///< Handle directory listing
};

/**
 * @brief Main function to start the FUSE filesystem.
 * 
 * Initializes and runs the FUSE event loop with the defined operations.
 *
 * @param argc Argument count
 * @param argv Argument vector
 * @return Result of fuse_main()
 */
int main(int argc, char *argv[]) {
    return fuse_main(argc, argv, &my_oper, NULL);
}


