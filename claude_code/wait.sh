# Wait for MCP to become ready, but fail fast instead of hanging forever.
TIMEOUT="${WAIT_TIMEOUT:-120}"
START_TS=$(date +%s)

while ! curl -s --head http://localhost:8000/ >/dev/null; do
    NOW_TS=$(date +%s)
    if [ $((NOW_TS - START_TS)) -ge "$TIMEOUT" ]; then
        echo "MCP service did not become ready within ${TIMEOUT}s" >&2
        exit 1
    fi
    sleep 1
done
