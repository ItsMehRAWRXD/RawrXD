/* ur_sync.h — residency lock / join wait (Win32) */
#ifndef UR_SYNC_H
#define UR_SYNC_H
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef struct {
    CRITICAL_SECTION cs;
    CONDITION_VARIABLE cv;
} UrSync;

static void ur_sync_init(UrSync *s)
{
    InitializeCriticalSection(&s->cs);
    InitializeConditionVariable(&s->cv);
}
static void ur_sync_kill(UrSync *s) { DeleteCriticalSection(&s->cs); }
static void ur_sync_lock(UrSync *s) { EnterCriticalSection(&s->cs); }
static void ur_sync_unlock(UrSync *s) { LeaveCriticalSection(&s->cs); }
static void ur_sync_wake(UrSync *s) { WakeAllConditionVariable(&s->cv); }
static void ur_sync_wait(UrSync *s)
{ SleepConditionVariableCS(&s->cv, &s->cs, INFINITE); }

#endif
