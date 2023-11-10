#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <openssl/md5.h>

// define ransomware names
char *ransomware_names[] = {"cryptxxx", "locky", "teslacrypt", "nullcrypto_ransom", "emptylockfile"};

// check if file is encrypted by ransomware
int check_encrypted(char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        return 0;
    }
    unsigned char magic[4];
    fread(magic, 1, 4, file);
    fclose(file);
    if (magic[0] == 0x01 && magic[1] == 0x00 && magic[2] == 0x00 && magic[3] == 0x00) {
        return 1;
    }
    return 0;
}

// check if file is encrypted by ransomware using magic number
int check_encrypted_magic(char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        return 0;
    }
    unsigned char magic[4];
    fread(magic, 1, 4, file);
    fclose(file);
    if (magic[0] == 0x7b && magic[1] == 0x5c && magic[2] == 0x72 && magic[3] == 0x6e) {
        return 1;
    }
    return 0;
}

// check if file is encrypted by ransomware using its signature
int check_encrypted_signature(char *filename) {
    // open file and get its size
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        return 0;
    }
    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // read file into memory
    unsigned char *buffer = (unsigned char *)malloc(filesize);
    fread(buffer, 1, filesize, file);
    fclose(file);

    // compute MD5 hash of file
    unsigned char md5[MD5_DIGEST_LENGTH];
    MD5(buffer, filesize, md5);
    free(buffer);

    // compare MD5 hash with ransomware's signature
    if (memcmp(md5, ransomware_signature, MD5_DIGEST_LENGTH) == 0) {
        return 1;
    }
    return 0;
}

// thread function to check and block files encrypted by ransomware
void *check_files(void *arg) {
    while (1) {
        // get the current time
        time_t t = time(NULL);
        struct tm tm = *localtime(&t);

        // scan all files in the system every minute
        if (tm.tm_sec == 0) {
            // add the root directory to the scan list
            scan_list.push_back("/");

            // scan all directories in the scan list
            while (!scan_list.empty()) {
                char *directory = scan_list.front();
                scan_list.pop_front();

                // open directory and get all files and directories
                DIR *dir = opendir(directory);
                if (dir == NULL) {
                    continue;
                }
                struct dirent *entry;
                while ((entry = readdir(dir)) != NULL) {
                    // ignore "." and ".."
                    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                        continue;
                    }

                    // check if the entry is a directory or a file
                    char file_path[1024];
                    sprintf(file_path, "%s/%s", directory, entry->d_name);
                    struct stat st;
                    if (stat(file_path, &st) == 0) {
                        if (S_ISDIR(st.st_mode)) {
                            // add the directory to the scan list
                            scan_list.push_back(file_path);
                        } else if (S_ISREG(st.st_mode)) {
                            // check if the file is encrypted by ransomware
                            if (check_encrypted(file_path)) {
                                // block the file by removing its write permissions
                                chmod(file_path, st.st_mode & ~S_IWUSR);
                            }
                        }
                    }
                }
                closedir(dir);
            }
        }

        // sleep for a second before checking again
        sleep(1);
    }
}

// function to start the file checking and blocking thread
void start_check_files() {
    pthread_t thread;
    pthread_create(&thread, NULL, check_files, NULL);
}

int main() {
    start_check_files();
    pause();
    return 0;
}
