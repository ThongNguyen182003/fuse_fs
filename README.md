# FUSE Encrypted Filesystem

This is a simple encrypted virtual filesystem built using **FUSE** and **AES-256-CBC** encryption.
Only **whitelisted applications** are allowed to read/write files via the mounted FUSE directory.
Unauthorized applications will receive a **Permission denied** error.

---

## Requirements

* Linux system
* FUSE 3
* OpenSSL development libraries

### Install dependencies (Debian/Ubuntu)

```bash
sudo apt install libfuse3-dev libssl-dev
```

---

## Build Instructions

Run the following command in the project root:

```bash
make
```

This will generate the executable `fuse_fs`.

To compile helper tools:

```bash
gcc read_fuse.c -o read_fuse
gcc read_fuse_error.c -o read_fuse_error
```

---

## Usage

### 1. Create required directories:

```bash
mkdir -p backend mountpoint
```

### 2. Encrypt and store files in the `backend/` directory manually. Example:

```bash
echo "fuse file 1" | openssl enc -aes-256-cbc \
  -K 3031323334353637383930313233343536373839303132333435363738393031 \
  -iv 30313233343536373839303132333435 \
  -nosalt -out backend/fuse_file.txt

echo "fuse file 2" | openssl enc -aes-256-cbc \
  -K 3031323334353637383930313233343536373839303132333435363738393031 \
  -iv 30313233343536373839303132333435 \
  -nosalt -out backend/fuse_file_2.txt
```

### 3. Mount the filesystem:

```bash
./fuse_fs mountpoint/
```

### 4. List files in mountpoint:

```bash
ls mountpoint/
```

### 5. Read files using whitelisted programs:

Using `cat`:

```bash
cat mountpoint/fuse_file.txt
```

Using access-tested program `read_fuse`:

```bash
./read_fuse fuse_file.txt
```

If you want to test access denial, use:

```bash
./read_fuse_error fuse_file.txt
```

---

## Whitelisting

Only the following process names are allowed to access decrypted files:

```c
const char *whitelist[] = {"bash", "cat", "echo", "read_fuse"};
```

Other applications will receive a `Permission denied` error when accessing files.

---

## Fuse Filesystem Test Cases

### Permission Denied / Not Implemented Commands

#### TC01 – Open file with vim Command
Command: 
```bash
vim mountpoint/fuse_file.txt
```
Result: READ ERRORS

Note: Pass

#### TC02 – Open file with less Command
Command: 
```bash
less mountpoint/fuse_file.txt
```
Result: READ ERRORS

Note: Pass

#### TC03 – Read file with Python Command
Command: 
```bash
python3 -c 'open("mountpoint/fuse_file.txt").read()'
```
Result: Permission denied

Note: Pass

#### TC04 – Open file with nano Command
Command: 
```bash
nano mountpoint/fuse_file.txt
```

Result: Permission denied

Note: Pass

#### TC05 – Copy file Command
Command: 
```bash
cp mountpoint/fuse_file.txt copied_fuse_file.txt
```
Result: Permission denied

Note: Pass

#### TC06 – Delete file Command
Command: 
```bash
rm mountpoint/fuse_file.txt
```
Result: Function not implemented

Note: Pass

#### TC07 – Rename file Command
Command: 
```bash
mv mountpoint/fuse_file.txt mountpoint/renamed.txt
```
Result: Function not implemented

Note: Pass

#### TC08 – Compile file with gcc Command
Command: 
```bash
gcc mountpoint/fuse_file.txt -o test_output
```
Result: Permission denied

Note: Pass

#### TC09 – Change permissions with chmod Command
Command: 
```bash
chmod 777 mountpoint/fuse_file.txt
```
Result: Function not implemented

Note: Pass

---

## Unmount

To unmount the FUSE filesystem:

```bash
fusermount3 -u mountpoint/
```

---

## Clean Up

To remove build artifacts:

```bash
make clean
```