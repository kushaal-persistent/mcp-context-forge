// Server-Sent Events over fetch().
//
// EventSource can't send an Authorization header, and the gateway authenticates with a
// Bearer token, so we read the stream with fetch() and parse the SSE frames ourselves.
// The gateway replays missed in-app deliveries when we send `Last-Event-ID`, so a
// reconnect does not lose alerts.

/**
 * Incremental SSE parser. Feed it text chunks; it calls onEvent({id, event, data, retry})
 * for each complete event. Comment lines (": keepalive") are ignored.
 */
export function createSseParser(onEvent, onActivity = () => {}) {
  let buf = '';
  let cur = { id: undefined, event: 'message', data: [], retry: undefined };

  function dispatch() {
    if (cur.data.length > 0) {
      onEvent({ id: cur.id, event: cur.event || 'message', data: cur.data.join('\n'), retry: cur.retry });
    }
    cur = { id: cur.id, event: 'message', data: [], retry: undefined };
  }

  function handleLine(line) {
    if (line === '') return dispatch();
    if (line.startsWith(':')) return; // comment / keepalive
    const i = line.indexOf(':');
    const field = i === -1 ? line : line.slice(0, i);
    let value = i === -1 ? '' : line.slice(i + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'data') cur.data.push(value);
    else if (field === 'event') cur.event = value;
    else if (field === 'id') cur.id = value;
    else if (field === 'retry') {
      const n = Number(value);
      if (Number.isFinite(n)) cur.retry = n;
    }
  }

  return {
    push(text) {
      if (!text) return;
      onActivity();
      buf += text;
      // A trailing "\r" might be the first half of "\r\n"; hold it until the next chunk.
      let hold = '';
      if (buf.endsWith('\r')) {
        hold = '\r';
        buf = buf.slice(0, -1);
      }
      const parts = buf.split(/\r\n|\n|\r/);
      buf = parts.pop() + hold;
      for (const line of parts) handleLine(line);
    },
  };
}

export function backoffDelay(attempt, { base = 1000, max = 30000, jitter = Math.random } = {}) {
  const exp = Math.min(max, base * 2 ** attempt);
  return Math.round(exp / 2 + (exp / 2) * jitter()); // 50%..100% of the exponential delay
}

/**
 * Keep a live connection to the alert stream.
 *
 * status values passed to onStatus:
 *   connecting | live | reconnecting | disabled (404: alerting off) | unauthorized (401/403) | stopped
 *
 * Returns { stop() }.
 */
export function connectAlertStream({
  url,
  getToken,
  onEvent,
  onStatus = () => {},
  fetchImpl = (...a) => fetch(...a),
  idleTimeoutMs = 45000, // gateway sends a keepalive every 15s
  sleep = (ms, signal) =>
    new Promise((resolve) => {
      const t = setTimeout(resolve, ms);
      signal.addEventListener('abort', () => { clearTimeout(t); resolve(); }, { once: true });
    }),
}) {
  const stopCtl = new AbortController();
  let lastEventId;
  let attempt = 0;

  async function run() {
    while (!stopCtl.signal.aborted) {
      const ctl = new AbortController();
      const onStop = () => ctl.abort();
      stopCtl.signal.addEventListener('abort', onStop, { once: true });
      let idleTimer;
      const armIdle = () => {
        clearTimeout(idleTimer);
        idleTimer = setTimeout(() => ctl.abort(), idleTimeoutMs);
      };
      try {
        onStatus(attempt === 0 ? 'connecting' : 'reconnecting');
        const headers = { Accept: 'text/event-stream', Authorization: `Bearer ${getToken()}` };
        if (lastEventId) headers['Last-Event-ID'] = lastEventId;
        armIdle();
        const res = await fetchImpl(url, { headers, signal: ctl.signal });
        if (res.status === 401 || res.status === 403) {
          onStatus('unauthorized');
          return;
        }
        if (res.status === 404) {
          onStatus('disabled');
          return;
        }
        if (!res.ok || !res.body) throw new Error(`stream HTTP ${res.status}`);

        onStatus('live');
        attempt = 0;
        const parser = createSseParser((ev) => {
          if (ev.id) lastEventId = ev.id;
          let payload = ev.data;
          try { payload = JSON.parse(ev.data); } catch { /* keep raw */ }
          onEvent({ ...ev, payload });
        }, armIdle);
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          parser.push(decoder.decode(value, { stream: true }));
        }
      } catch (e) {
        if (stopCtl.signal.aborted) break;
        // network error or idle timeout: fall through to reconnect
      } finally {
        clearTimeout(idleTimer);
        stopCtl.signal.removeEventListener('abort', onStop);
      }
      if (stopCtl.signal.aborted) break;
      onStatus('reconnecting');
      await sleep(backoffDelay(attempt++), stopCtl.signal);
    }
    onStatus('stopped');
  }

  run();
  return { stop: () => stopCtl.abort() };
}
