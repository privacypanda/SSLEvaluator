//
//  ssl_thread.h
//  SSLEvaluator
//
//  Created by Daniel Bates on 17/05/2021.
//

#ifndef ssl_thread_h
#define ssl_thread_h

#include <stdio.h>

#include <pthread.h>

int THREAD_setup(void);
int THREAD_cleanup(void);

#define MUTEX_TYPE pthread_mutex_t
#define MUTEX_SETUP(x) pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))
#define THREAD_ID pthread_self( )


/* This array will store all of the mutexes available to OpenSSL. */
static MUTEX_TYPE *mutex_buf = NULL;

#endif /* ssl_thread_h */
