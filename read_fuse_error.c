#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Thuc hien doc noi dung file da duoc ma hoa.
 *
 * @param path Duong dan den file trong mountpoint.
 * @return 0 neu thanh cong, ma loi neu that bai.
 */
int main(int argc, char *argv[]) {
    char filepath[512];
    FILE *f;
    char buf[1024];
    size_t len;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename in mountpoint>\n", argv[0]);
        return 1;
    }

    snprintf(filepath, sizeof(filepath), "mountpoint/%s", argv[1]);

    f = fopen(filepath, "r");
    if (!f) {
        perror("Cannot open file");
        return 1;
    }

    len = fread(buf, 1, sizeof(buf) - 1, f);
    buf[len] = '\0';

    printf("Decrypted content of %s:\n%s\n", argv[1], buf);

    fclose(f);
    return 0;
}
