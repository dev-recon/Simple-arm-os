#ifndef _TIME_H
#define _TIME_H

#include <stddef.h>
#include <stdint.h>

typedef uint32_t useconds_t;

struct timespec {
    long tv_sec;   /* secondes */
    long tv_nsec;  /* nanosecondes */
};

typedef struct {
    int year;   /* Année complète, ex: 2023 */
    int month;  /* Mois 1-12 */
    int day;    /* Jour 1-31 */
    int hour;   /* Heure 0-23 */
    int minute; /* Minute 0-59 */
    int second; /* Seconde 0-59 */
} datetime_t;


int nanosleep(const struct timespec* req, struct timespec* rem);
unsigned int sleep(unsigned int seconds);
int usleep(useconds_t usec);

#endif /* _TIME_H */