/*
 * Interfaces exported by our tokenwatcher module
 */

#ifndef __TOKENWATCHER_H__
#define __TOKENWATCHER_H__ 1

/*
 * Register an event handler with TKTokenWatcher
 */

extern void start_token_watcher(void);

/*
 * De-register the TKTokenWatcher event handler
 */

extern void stop_token_watcher(void);

#endif /* __TOKENWATCHER_H__ */
