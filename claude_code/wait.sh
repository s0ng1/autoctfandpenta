# Wait for MCP to become ready, but fail fast instead of hanging forever.
# The Claude config points at /mcp, so readiness should check the actual MCP endpoint.
TIMEOUT="${WAIT_TIMEOUT:-120}"
START_TS=$(date +%s)
LAST_LOG_TS=0

while true; do
    HTTP_CODE="$(curl -sS -o /dev/null -w '%{http_code}' http://localhost:8000/mcp || true)"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "406" ]; then
        break
    fi

    NOW_TS=$(date +%s)
    ELAPSED=$((NOW_TS - START_TS))

    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
        echo "MCP service did not become ready within ${TIMEOUT}s" >&2
        exit 1
    fi

    if [ $((NOW_TS - LAST_LOG_TS)) -ge 10 ]; then
        LAST_LOG_TS="$NOW_TS"
        echo "[wait.sh] waiting for MCP at http://localhost:8000/mcp (${ELAPSED}s/${TIMEOUT}s), last HTTP=${HTTP_CODE}" >&2
    fi

    sleep 1
done
