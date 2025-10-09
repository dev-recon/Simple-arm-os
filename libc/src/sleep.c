#include <unistd.h>
#include <time.h>

extern int nanosleep(const struct timespec *req, struct timespec *rem);

unsigned int sleep(unsigned int seconds) {
    struct timespec req, rem;
    
    req.tv_sec = seconds;
    req.tv_nsec = 0;
    
    if (nanosleep(&req, &rem) < 0) {
        /* Interrompu par un signal */
        return rem.tv_sec;
    }
    
    return 0;
}

int usleep(useconds_t usec) {
    struct timespec req;
    
    req.tv_sec = usec / 1000000;
    req.tv_nsec = (usec % 1000000) * 1000;
    
    return nanosleep(&req, NULL);
}