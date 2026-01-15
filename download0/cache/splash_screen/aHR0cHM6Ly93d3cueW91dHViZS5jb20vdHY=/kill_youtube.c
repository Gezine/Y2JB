// https://github.com/BenNoxXD/PS5-BDJ-HEN-loader/tree/main/HENloader_C_part
/*
 * Copyright (c) 2025 BenNox_XD
 *
 * This file is part of PS5-BDJ-HEN-loader and is licensed under the MIT License.
 * See the LICENSE file in the root of the project for full license information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/types.h>
#include <ps5/kernel.h>

#define TITLE_ID_LEN 10

// Notification structure
typedef struct {
    char unused[45];
    char message[3075];
} notify_request_t;

// External PS5 system functions
int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);
int sceLncUtilGetAppIdOfRunningBigApp();
int sceLncUtilGetAppTitleId(uint32_t app_id, char *title_id);
int sceLncUtilSuspendApp(uint32_t app_id);
int sceLncUtilKillApp(uint32_t app_id);

// Target configuration
const char *target_process = "eboot.bin";
const char *target_title_id = "PPSA01650";
const char *target_friendly_name = "Youtube";

// Send notification to PS5
void send_notification(const char *fmt, ...) {
    notify_request_t req = {0};
    va_list args;
    va_start(args, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, args);
    va_end(args);
    sceKernelSendNotificationRequest(0, &req, sizeof req, 0);
}

// Get PID by process name
pid_t get_pid(const char *process_name) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    size_t buf_size;
    void *buf = NULL;

    if (sysctl(mib, 4, NULL, &buf_size, NULL, 0)) return -1;

    buf = malloc(buf_size);
    if (!buf) return -1;

    if (sysctl(mib, 4, buf, &buf_size, NULL, 0)) {
        free(buf);
        return -1;
    }

    pid_t pid = -1;
    for (void *ptr = buf; ptr < (buf + buf_size); ptr += ((struct kinfo_proc *)ptr)->ki_structsize) {
        struct kinfo_proc *ki = (struct kinfo_proc *)ptr;
        if (ki->ki_structsize < sizeof(struct kinfo_proc)) break;
        if (strncmp(ki->ki_comm, process_name, sizeof(ki->ki_comm)) == 0) {
            pid = ki->ki_pid;
            break;
        }
    }

    free(buf);
    return pid;
}

// Kill disc player application
int kill_disc_player(const char *target_process, const char *target_title_id, const char *target_friendly_name) {    
    // Getting App ID of target_title_id
    uint32_t app_id = sceLncUtilGetAppIdOfRunningBigApp();
    printf("sceLncUtilGetAppIdOfRunningBigApp returned: 0x%08x\n", app_id);

    if (app_id == 0xffffffff) {
        printf("No App is running!\nExiting...\n");
        return 1;
    }

    char title_id[TITLE_ID_LEN] = {0};

    if (sceLncUtilGetAppTitleId(app_id, title_id) != 0) {
        strncpy(title_id, "UNKNOWN", TITLE_ID_LEN);
    }
    printf("App ID: 0x%08x\nTitle ID: %s\n", app_id, title_id);

    // Title ID check
    if (strcmp(title_id, target_title_id) != 0) {
        printf("Title ID mismatch: expected %s, got %s\n", target_title_id, title_id);
        return 1;
    }
    
    // Attempt to suspend the app
    if (sceLncUtilSuspendApp(app_id) != 0) {
        printf("Failed to suspend app with ID: 0x%08x\n", app_id);
        return 1;
    }

    printf("Successfully suspended app: %s\n", target_title_id);

    // Waiting for 2 seconds to ensure being on the home screen
    printf("Waiting for 2 seconds to ensure being on the home screen...\n");
    sleep(2);

    // Sending SIGTERM to target_process
    printf("Sending SIGTERM to %s\n", target_process);
    pid_t pid = get_pid(target_process);
    if (pid == -1) {
        printf("%s not found.\n", target_process);
        return 1;
    }

    printf("%s has PID: %d\n", target_process, pid);
    if (kill(pid, SIGTERM) == -1) {
        perror("kill failed");
    } else {
        printf("Signal SIGTERM sent to process %d\n", pid);
    }
    
    send_notification("Attempting to kill %s...", target_friendly_name);

    printf("Attempting to kill: %s\n", target_process);
    int result = sceLncUtilKillApp(app_id);
    printf("result of sceLncUtilKillApp: %d\n", result);
    if (result != 0) {
        printf("The app %s has probably crashed or the kill failed, investigating...\n", title_id);
        send_notification("The app %s has probably crashed or the kill failed, investigating...", target_friendly_name);
        
        // Check if the app has crashed and is "terminated"; this is ok-ish
        if (sceLncUtilGetAppIdOfRunningBigApp() != 0xffffffff) {
            printf("Failed to kill %s, app is still running\n", target_process);
            send_notification("Failed to kill %s, app is still running", target_friendly_name);
            return 1;
        } else {
            printf("The app %s has crashed, this is considered as \"closed\", continuing...\n", target_process);
            send_notification("The app %s has crashed, this is considered as \"closed\", continuing...", target_friendly_name);
        }

    } else {
        printf("Successfully killed %s\n", title_id);
        send_notification("Successfully killed %s", target_friendly_name);
    }

    return 0;
}

int main() {
    kill_disc_player(target_process, target_title_id, target_friendly_name);
    return 0;
}