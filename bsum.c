#include <blake2.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void printUsage(char *argv0)
{
    fprintf(stderr, "Usage: %s <keyfile> <datafile> [keysize]\n", argv0);
}

int main(int argc, char *argv[])
{
    int hashsize = 512;
    const char *keyfile = NULL;
    const char *datafile = NULL;

    if (argc < 3)
    {
        printUsage(argv[0]);
        return -1;
    }

    if (argc > 3)
    {
        int size = atoi(argv[3]);
        if (!(size % 8) && size > 0 && size <= 512)
        {
            hashsize = size;
        }
    }

    fprintf(stderr, "Using Hash Size %d\n", hashsize);

    hashsize /= 8;

    keyfile = argv[1];
    datafile = argv[2];

    FILE *keyhandle = fopen(keyfile, "rb");
    if (keyhandle == NULL)
    {
        perror("Couldn't open key file");
        return -1;
    }

    fseek(keyhandle, 0, SEEK_END);
    off_t keylen = ftell(keyhandle);

    FILE *datahandle = fopen(datafile, "rb");
    if (datahandle == NULL)
    {
        perror("Couldn't open data file");
        fclose(keyhandle);
        return -1;
    }

    fseek(datahandle, 0, SEEK_END);
    off_t datalen = ftell(datahandle);

    rewind(keyhandle);
    uint8_t *key = (uint8_t *)malloc(keylen);
    int res = fread(key, keylen, 1, keyhandle);
    if (res < 1)
    {
        perror("Couldn't read file");
        fclose(keyhandle);
        fclose(datahandle);
        free(key);
        return -1;
    }

    rewind(datahandle);
    uint8_t *data = (uint8_t *)malloc(datalen);
    res = fread(data, datalen, 1, datahandle);
    if (res < 1)
    {
        perror("Couldn't read file");
        fclose(keyhandle);
        fclose(datahandle);
        free(key);
        free(data);
        return -1;
    }

    fclose(keyhandle);
    fclose(datahandle);

    uint8_t *hash = (uint8_t *)malloc(hashsize);
    fprintf(stderr, "Key size: %ld, Data size: %ld\n", keylen, datalen);
    int result = blake2b(hash, data, key, hashsize, datalen, keylen);

    free(data);
    free(key);

    fwrite(hash, hashsize, 1, stdout);
    free(hash);
    return 0;
}
