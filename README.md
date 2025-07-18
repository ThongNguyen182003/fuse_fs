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
sudo apt install libfuse3-dev libssl-dev fuse3
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
# Create the mountpoint directory in the current directory
mkdir mountpoint

# Create the /opt/backend directory with root permissions
sudo mkdir -p /opt/backend

# Change the ownership of /opt/backend to the current user
sudo chown -R user_name:user_name /opt/backend

# Set read, write, and execute permissions for the owner, and read and execute for others
sudo chmod -R 755 /opt/backend
```


### 2. Encrypt and store files in the `backend/` directory manually. Example:

```bash
echo "fuse file 1" | openssl enc -aes-256-cbc \
  -K 3031323334353637383930313233343536373839303132333435363738393031 \
  -iv 30313233343536373839303132333435 \
  -nosalt -out /opt/backend/fuse_file.txt

echo "fuse file 2" | openssl enc -aes-256-cbc \
  -K 3031323334353637383930313233343536373839303132333435363738393031 \
  -iv 30313233343536373839303132333435 \
  -nosalt -out /opt/backend/fuse_file_2.txt
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
