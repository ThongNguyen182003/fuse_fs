/**
 * @file fuse_core.h
 * @brief Header file containing function declarations and constants
 *        for custom encrypted FUSE filesystem.
 */

#ifndef FUSE_CORE_H
#define FUSE_CORE_H

#define FUSE_USE_VERSION 35

#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pwd.h>
#include <openssl/evp.h>
#include <dirent.h>

extern const char *backend_dir;
extern const char *log_path;
extern const unsigned char aes_key[32];
extern const unsigned char aes_iv[16];

void log_process_info();
int get_process_name(char *out_name, size_t size);
int is_app_in_whitelist(const char *app_name);
int aes_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext);
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext);

// FUSE operations
int my_getattr(const char *path, struct stat *st, struct fuse_file_info *fi);
int my_open(const char *path, struct fuse_file_info *fi);
int my_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int my_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int my_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags);

#endif


