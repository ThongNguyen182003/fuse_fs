/**
 * @file fuse_core.c
 */

#include "fuse_core.h"

const char *whitelist[] = {"bash", "cat", "echo", "read_fuse"};
const int num_whitelist = 4;

const char *backend_dir = "/home/thong/fuse/backend/";
const char *log_path = "/home/thong/fuse/fuse.log";

const unsigned char aes_key[32] = "01234567890123456789012345678901";
const unsigned char aes_iv[16] = "0123456789012345";

/**
 * @brief Luu thong bao loi vao file log.
 *
 * @param message Thong bao loi can ghi vao log.
 */
void log_error(const char *message) {
    FILE *log;

    log = fopen(log_path, "a");
    if (log) {
        fprintf(log, "[ERROR] %s\n", message);
        fclose(log);
    }
}

/**
 * @brief Luu thong tin cua tien trinh hien tai (PID, UID, GID, etc.).
 */
void log_process_info() {
    struct fuse_context *ctx;
    pid_t pid;
    uid_t uid;
    gid_t gid;
    char comm[256] = "unknown";
    char exe_path[512] = "unknown";
    char path[256];
    FILE *f;
    ssize_t len;
    struct passwd *pw;
    const char *user;
    FILE *log;

    ctx = fuse_get_context();
    if (!ctx) {
        log_error("Failed to get fuse context\n");
        return;
    }

    pid = ctx->pid;
    uid = ctx->uid;
    gid = ctx->gid;

    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    f = fopen(path, "r");
    if (f) {
        if (fgets(comm, sizeof(comm), f)) {
            comm[strcspn(comm, "\n")] = 0;
        } else {
            log_error("Failed to read from /proc/[pid]/comm\n");
        }
        if (fclose(f) != 0) {
            log_error("Failed to close /proc/[pid]/comm file\n");
        }
    } else {
        log_error("Failed to open /proc/[pid]/comm\n");
    }

    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    len = readlink(path, exe_path, sizeof(exe_path) - 1);
    if (len != -1) {
        exe_path[len] = '\0';
    } else {
        log_error("Failed to readlink /proc/[pid]/exe\n");
    }

    pw = getpwuid(uid);
    user = pw ? pw->pw_name : "unknown";

    log = fopen(log_path, "a");
    if (log) {
        fprintf(log, "[PID:%d] CMD:%s EXE:%s UID:%d (%s) GID:%d\n",
                pid, comm, exe_path, uid, user, gid);
        fclose(log);
    } else {
        log_error("Failed to open log file for process info\n");
    }
}

/**
 * @brief Lay ten tien trinh cua ung dung goi.
 *
 * @param out_name Bo dem de luu ten tien trinh.
 * @param size Kich thuoc cua bo dem.
 * @return 0 neu thanh cong, -1 neu that bai.
 */
int get_process_name(char *out_name, size_t size) {
    pid_t pid;
    char path[256];
    FILE *f;

    pid = fuse_get_context()->pid;

    snprintf(path, sizeof(path), "/proc/%d/comm", pid);

    f = fopen(path, "r");
    if (!f) {
        log_error("Failed to open /proc/[pid]/comm in get_process_name\n");
        return -1;
    }

    if (!fgets(out_name, size, f)) {
        log_error("Failed to read process name\n");
        fclose(f);
        return -1;
    }

    out_name[strcspn(out_name, "\n")] = 0;

    if (fclose(f) != 0) {
        log_error("Failed to close /proc/[pid]/comm in get_process_name\n");
    }

    return 0;
}

/**
 * @brief Kiem tra xem ung dung co trong whitelist hay khong.
 *
 * @param app_name Ten cua ung dung can kiem tra.
 * @return 1 neu co trong whitelist, 0 neu khong co.
 */
int is_app_in_whitelist(const char *app_name) {
    int i;

    for (i = 0; i < num_whitelist; i++) {
        if (strcmp(whitelist[i], app_name) == 0)
            return 1;
    }

    return 0;
}

/**
 * @brief Ma hoa du lieu bang AES-256-CBC.
 *
 * @param plaintext Du lieu dau vao can ma hoa.
 * @param plaintext_len Do dai cua du lieu dau vao.
 * @param ciphertext Bo dem de luu du lieu da ma hoa.
 * @return Do dai cua du lieu ma hoa, hoac -1 neu co loi.
 */
int aes_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log_error("Failed to create encryption context\n");
        return -1;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv)) {
        log_error("EVP_EncryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        log_error("EVP_EncryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        log_error("EVP_EncryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

/**
 * @brief Giai ma du lieu su dung AES-256-CBC.
 *
 * @param ciphertext Du lieu da ma hoa.
 * @param ciphertext_len Do dai cua du lieu da ma hoa.
 * @param plaintext Bo dem de luu du lieu da giai ma.
 * @return Do dai cua du lieu giai ma, hoac -1 neu co loi.
 */
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log_error("Failed to create decryption context\n");
        return -1;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv)) {
        log_error("EVP_DecryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        log_error("EVP_DecryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        log_error("EVP_DecryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

/**
 * @brief Thuc hien thao tac getattr. Thiet lap thuoc tinh file.
 *
 * @param path Duong dan den file.
 * @param st Con tro toi struct stat de dien thong tin.
 * @param fi Thong tin fuse file (khong su dung).
 * @return 0 neu thanh cong, ma loi neu that bai.
 */
int my_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {

    char fullpath[512];
    struct stat real_stat;

    (void) fi;

    memset(st, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
        return 0;
    }

    snprintf(fullpath, sizeof(fullpath), "%s%s", backend_dir, path + 1);
    if (access(fullpath, F_OK) != 0) return -ENOENT;

    if (stat(fullpath, &real_stat) != 0) return -ENOENT;
    st->st_mode = S_IFREG | 0644;
    st->st_nlink = 1;
    st->st_size = real_stat.st_size;
    
    return 0;
}

/**
 * @brief Thuc hien thao tac mo file. Kiem tra xem file co ton tai hay khong.
 *
 * @param path Duong dan den file.
 * @param fi Con tro toi thong tin file trong fuse.
 * @return 0 neu thanh cong, -ENOENT neu file khong ton tai.
 */
int my_open(const char *path, struct fuse_file_info *fi) {
    char fullpath[512];

    snprintf(fullpath, sizeof(fullpath), "%s%s", backend_dir, path + 1);

    if (access(fullpath, F_OK) != 0) 
        return -ENOENT;

    return 0;
}

/**
 * @brief Thuc hien thao tac doc file. Giai ma va tra ve noi dung neu ung dung trong whitelist.
 *
 * @param path Duong dan den file.
 * @param buf Bo dem de luu noi dung da giai ma.
 * @param size So byte can doc.
 * @param offset Vi tri bat dau doc.
 * @param fi Con tro toi thong tin file trong fuse.
 * @return So byte da doc, hoac ma loi.
 */
int my_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    log_process_info();
    char pname[256];
    
    if (get_process_name(pname, sizeof(pname)) != 0 || !is_app_in_whitelist(pname))
        return -EACCES;

    char fullpath[512];
    snprintf(fullpath, sizeof(fullpath), "%s%s", backend_dir, path + 1);

    FILE *f = fopen(fullpath, "rb");
    if (!f) {
        log_error("Failed to open file for reading\n");
        return -ENOENT;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        log_error("Failed to seek to end of file\n");
        fclose(f);
        return -EIO;
    }

    long fsize = ftell(f);
    if (fsize < 0) {
        log_error("Failed to get file size\n");
        fclose(f);
        return -EIO;
    }

    rewind(f);

    unsigned char *encrypted = malloc(fsize);
    if (!encrypted) {
        log_error("Failed to allocate memory for encrypted data\n");
        fclose(f);
        return -ENOMEM;
    }

    if (fread(encrypted, 1, fsize, f) != fsize) {
        log_error("Failed to read encrypted data\n");
        fclose(f);
        free(encrypted);
        return -EIO;
    }

    if (fclose(f) != 0) {
        log_error("Failed to close file after reading\n");
    }

    unsigned char *decrypted = malloc(fsize);
    if (!decrypted) {
        log_error("Failed to allocate memory for decrypted data\n");
        free(encrypted);
        return -ENOMEM;
    }

    int dec_len = aes_decrypt(encrypted, fsize, decrypted);
    free(encrypted);
    if (dec_len < 0) {
        free(decrypted);
        return -EIO;
    }

    if (offset < dec_len) {
        if (offset + size > dec_len)
            size = dec_len - offset;
        memcpy(buf, decrypted + offset, size);
    } else {
        size = 0;
    }

    free(decrypted);
    return size;
}

/**
 * @brief Thuc hien thao tac write. Ma hoa noi dung va ghi vao file.
 *
 * @param path Duong dan den file.
 * @param buf Bo dem chua du lieu can ma hoa.
 * @param size So byte can ghi.
 * @param offset Vi tri bat dau ghi (khong su dung).
 * @param fi Con tro toi thong tin file trong fuse.
 * @return So byte da ghi, hoac ma loi am duong.
 */
int my_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    char pname[256];
    char fullpath[512];
    unsigned char encrypted[4096];
    int enc_len;
    FILE *f;

    log_process_info();

    if (get_process_name(pname, sizeof(pname)) != 0 || !is_app_in_whitelist(pname))
        return -EACCES;

    snprintf(fullpath, sizeof(fullpath), "%s%s", backend_dir, path + 1);

    enc_len = aes_encrypt((const unsigned char *)buf, size, encrypted);
    if (enc_len < 0) return -EIO;

    f = fopen(fullpath, "wb");
    if (!f) {
        log_error("Failed to open file for writing\n");
        return -EIO;
    }

    if (fwrite(encrypted, 1, enc_len, f) != enc_len) {
        log_error("Failed to write encrypted data\n");
        fclose(f);
        return -EIO;
    }

    if (fclose(f) != 0) {
        log_error("Failed to close file after writing\n");
    }

    return size;
}

/**
 * @brief Thuc hien thao tac readdir. Liet ke cac file thuong trong thu muc backend.
 *
 * @param path Duong dan can doc.
 * @param buf Bo dem de luu cac muc thu muc.
 * @param filler Callback de them cac muc vao.
 * @param offset Vi tri bat dau (khong su dung).
 * @param fi Con tro toi thong tin file trong fuse.
 * @param flags Cac co che readdir cua fuse.
 * @return 0 neu thanh cong, -ENOENT neu that bai.
 */
int my_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
               off_t offset, struct fuse_file_info *fi,
               enum fuse_readdir_flags flags) {
    (void) offset;
    (void) fi;
    (void) flags;

    if (strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    DIR *dir;
    struct dirent *entry;

    dir = opendir(backend_dir);
    if (!dir) {
        log_error("Failed to open backend directory\n");
        return -ENOENT;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            filler(buf, entry->d_name, NULL, 0, 0);
        }
    }

    if (closedir(dir) != 0) {
        log_error("Failed to close backend directory\n");
    }

    return 0;
}
