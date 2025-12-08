#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <minizip/unzip.h>
#include <fcntl.h>
#include <curl/curl.h>

unsigned int rwx = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH;
unsigned int rx = S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;

typedef struct
{
    char unused[45];
    char message[3075];
} notify_request_t;

int sceKernelDebugOutText(int a1, const char *fmt);
int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);

typedef struct
{
    char *name;
    unsigned *pre_permission;
    unsigned *post_permission;
} Folder;

int decend(Folder *paths[], int position, char *root);
int download_and_extract(char *path);
int download_file(char *url, char *destination);
int extract_zip(const char *zip_path, const char *extract_dir);
void apply_permissions(char *path, unsigned int *permissions);
void notify(const char *restrict format, ...);
void send_notification(const char *fmt, ...);

int main()
{
    Folder user = {
        .name = "user",
    };
    Folder download = {
        .name = "download",
    };
    Folder ppsa = {
        .name = "PPSA01650",
        .pre_permission = &rwx,
        .post_permission = &rx,
    };
    Folder *paths[] = {&user, &download, &ppsa, NULL};

    notify("Y2JB cache installer: Attempting to install Y2JB");

    curl_global_init(CURL_GLOBAL_ALL);

    if (decend(paths, 0, "") < 0)
    {
        notify("Y2JB cache installer: Installer failed!");
        return 1;
    }

    notify("Y2JB cache installer: Installed successfully!");
    return 0;
}

void apply_permissions(char *path, unsigned int *permissions)
{
    if (permissions)
    {
        notify("Y2JB cache installer: Setting permissions: %s, o%o", path, *permissions);
        chmod(path, *permissions);
    }
}

int download_file(char *url, char *destination)
{
    CURL *curl = curl_easy_init();

    if (curl)
    {
        FILE *fp = fopen(destination, "wb+");

        if (!fp)
        {
            curl_easy_cleanup(curl);
            return -1;
        }

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
        
        CURLcode result = curl_easy_perform(curl);
        
        curl_easy_cleanup(curl);
        fclose(fp);

        if (result)
        {
            return -1;
        }
    }

    return 0;
}

int download_and_extract(char *path)
{
    char py_file[4096] = {};
    char zip_file[4096] = {};
    char dat_file[4096] = {};
    int error = 0;
    char *url = "https://github.com/Gezine/Y2JB/releases/download/Y2JB-1.2.1/Y2JB_download0_1.2.1.zip";

    strcpy(zip_file, path);
    strcat(zip_file, "/archive.zip");
    strcpy(py_file, path);
    strcat(py_file, "/appinfo_editor.py");
    strcpy(dat_file, path);
    strcat(dat_file, "/download0.dat");
    notify("Y2JB cache installer: Attempting to download: %s", url);

    if (download_file(url, zip_file) < 0)
    {
        notify("Y2JB cache installer: Download Failed");
        return -1;
    }

    notify("Y2JB cache installer: Download Complete");
    notify("Y2JB cache installer: Unpacking");
    extract_zip(zip_file, path);
    unlink(zip_file);
    unlink(py_file);
    notify("Y2JB cache installer: Unpacking... Done");
    apply_permissions(dat_file, &rx);
    return error;
}

int decend(Folder *paths[], int position, char *root)
{
    Folder *current = paths[position];

    if (current == NULL)
    {
        return download_and_extract(root);
    }

    char path[4096] = {};
    struct stat stats;
    int res;

    strcpy(path, root);
    strcat(path, "/");
    strcat(path, current->name);
    res = stat(path, &stats);

    if (res < 0)
    {
        mkdir(path, rwx);
    }

    apply_permissions(path, current->pre_permission);
    res = decend(paths, position + 1, path);

    if (res >= 0)
    {
        apply_permissions(path, current->post_permission);
    }

    return res;
}

int extract_zip(const char *zip_path, const char *extract_dir)
{
    unzFile zip = unzOpen(zip_path);

    if (!zip)
    {
        return -1;
    }

    char filename[512];
    char full_path[1024];
    unz_file_info file_info;

    if (unzGoToFirstFile(zip) == UNZ_OK)
    {
        do
        {
            unzGetCurrentFileInfo(zip, &file_info, filename, sizeof(filename), NULL, 0, NULL, 0);
            snprintf(full_path, sizeof(full_path), "%s/%s", extract_dir, filename);

            if (strstr(filename, "/"))
            {
                continue;
            }

            if (unzOpenCurrentFile(zip) != UNZ_OK)
            {
                continue;
            }

            int out = open(full_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

            if (out == -1)
            {
                unzCloseCurrentFile(zip);
                continue;
            }

            char buffer[512 * 2560];
            int bytes;

            while ((bytes = unzReadCurrentFile(zip, buffer, sizeof(buffer))) > 0)
            {
                write(out, buffer, bytes);
            }

            close(out);
            unzCloseCurrentFile(zip);
        } while (unzGoToNextFile(zip) == UNZ_OK);
    }

    unzClose(zip);
    return 0;
}

void notify(const char *restrict format, ...)
{
    char buffer[512];
    va_list args;

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    send_notification(buffer);
    strcat(buffer, "\n");
    sceKernelDebugOutText(0, buffer);
}

void send_notification(const char *fmt, ...)
{
    notify_request_t req = {0};
    va_list args;

    va_start(args, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, args);
    va_end(args);
    sceKernelSendNotificationRequest(0, &req, sizeof req, 0);
}