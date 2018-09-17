/*
 * Copyright 2011-2012 Con Kolivas
 * Copyright 2013 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include "logging.h"

bool opt_log_output = false;

/* per default priorities higher than LOG_NOTICE are logged */
int opt_log_level = LOG_NOTICE;

pthread_mutex_t console_lock;

static void my_log_curses(int prio, const char *datetime, const char *str, bool force)
{
    if (prio != LOG_ERR)
        return;

    /* Mutex could be locked by dead thread on shutdown so forcelog will
     * invalidate any console lock status. */
    if (force)
    {
        pthread_mutex_trylock(&console_lock);
        pthread_mutex_unlock(&console_lock);
    }
#ifdef HAVE_CURSES
    extern bool use_curses;
    if (use_curses && log_curses_only(prio, datetime, str))
        ;
    else
#endif
    {
        pthread_mutex_lock(&console_lock);
        fprintf(stderr, "%s%s%s", datetime, str, "                    \n");
        pthread_mutex_unlock(&console_lock);
    }
}

/* high-level logging function, based on global opt_log_level */

/*
 * log function
 */
void _applog(int prio, const char *str, bool force)
{
    if (1)
    {
        char datetime[64];
        struct timeval tv = {0, 0};
        struct tm *tm;

        gettimeofday(&tv, NULL);

        const time_t tmp_time = tv.tv_sec;
        int ms = (int)(tv.tv_usec / 1000);
        tm = localtime(&tmp_time);

        snprintf(datetime, sizeof(datetime), " [%d-%02d-%02d %02d:%02d:%02d.%03d] ",
                 tm->tm_year + 1900,
                 tm->tm_mon + 1,
                 tm->tm_mday,
                 tm->tm_hour,
                 tm->tm_min,
                 tm->tm_sec, ms);

        /* Only output to stderr if it's not going to the screen as well */
        if (!isatty(fileno((FILE *)stderr)))
        {
            fprintf(stderr, "%s%s\n", datetime, str);   /* atomic write to stderr */
            fflush(stderr);
        }

        my_log_curses(prio, datetime, str, force);
    }
}

void _simplelog(int prio, const char *str, bool force)
{
    if (1)
    {
        /* Only output to stderr if it's not going to the screen as well */
        if (!isatty(fileno((FILE *)stderr)))
        {
            fprintf(stderr, "%s\n", str);   /* atomic write to stderr */
            fflush(stderr);
        }

        my_log_curses(prio, "", str, force);
    }
}
