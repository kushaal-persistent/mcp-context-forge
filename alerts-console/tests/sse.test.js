import test from 'node:test';
import assert from 'node:assert/strict';
import { createSseParser, backoffDelay, connectAlertStream } from '../src/lib/sse.js';

function collect() {
  const events = [];
  return { events, parser: createSseParser((e) => events.push(e)) };
}

test('parses a single event with id, event and data', () => {
  const { events, parser } = collect();
  parser.push('id: c1\nevent: alert\ndata: {"a":1}\n\n');
  assert.equal(events.length, 1);
  assert.deepEqual(events[0], { id: 'c1', event: 'alert', data: '{"a":1}', retry: undefined });
});

test('ignores keepalive comments', () => {
  const { events, parser } = collect();
  parser.push(': keepalive\n\n');
  assert.equal(events.length, 0);
});

test('handles events split across arbitrary chunk boundaries', () => {
  const { events, parser } = collect();
  const raw = 'id: 9\nevent: alert\ndata: {"title":"x"}\n\n';
  for (const ch of raw) parser.push(ch);
  assert.equal(events.length, 1);
  assert.equal(events[0].id, '9');
  assert.equal(events[0].data, '{"title":"x"}');
});

test('handles CRLF split between chunks without producing a phantom empty line', () => {
  const { events, parser } = collect();
  parser.push('data: one\r');
  parser.push('\n\r\n');
  parser.push('data: two\r\n\r\n');
  assert.deepEqual(events.map((e) => e.data), ['one', 'two']);
});

test('joins multi-line data with newlines', () => {
  const { events, parser } = collect();
  parser.push('data: a\ndata: b\n\n');
  assert.equal(events[0].data, 'a\nb');
});

test('backoff grows, is capped, and stays within 50-100% of the exponential value', () => {
  assert.equal(backoffDelay(0, { jitter: () => 0 }), 500);
  assert.equal(backoffDelay(0, { jitter: () => 1 }), 1000);
  assert.equal(backoffDelay(3, { jitter: () => 1 }), 8000);
  assert.equal(backoffDelay(20, { jitter: () => 1 }), 30000);
});

function streamOf(chunks) {
  const enc = new TextEncoder();
  let i = 0;
  return {
    getReader: () => ({ read: async () => (i < chunks.length ? { value: enc.encode(chunks[i++]), done: false } : { done: true }) }),
  };
}

test('reconnects and sends Last-Event-ID from the last received event', async () => {
  const seenHeaders = [];
  const statuses = [];
  const got = [];
  let call = 0;
  let stream;
  const fetchImpl = async (_url, { headers }) => {
    seenHeaders.push({ ...headers });
    call += 1;
    if (call === 1) return { ok: true, status: 200, body: streamOf(['id: c1\nevent: alert\ndata: {"n":1}\n\n']) };
    // second connection: stay open until stopped
    queueMicrotask(() => stream.stop());
    return { ok: true, status: 200, body: streamOf([]) };
  };
  stream = connectAlertStream({
    url: '/x',
    getToken: () => 'tok',
    fetchImpl,
    sleep: async () => {},
    onStatus: (s) => statuses.push(s),
    onEvent: (e) => got.push(e.payload),
  });
  await new Promise((r) => setTimeout(r, 50));
  assert.deepEqual(got, [{ n: 1 }]);
  assert.equal(seenHeaders[0]['Last-Event-ID'], undefined);
  assert.equal(seenHeaders[1]['Last-Event-ID'], 'c1');
  assert.equal(seenHeaders[0].Authorization, 'Bearer tok');
  assert.ok(statuses.includes('live'));
});

test('stops retrying on 401 and reports unauthorized', async () => {
  const statuses = [];
  let calls = 0;
  connectAlertStream({
    url: '/x',
    getToken: () => 't',
    fetchImpl: async () => { calls += 1; return { ok: false, status: 401 }; },
    sleep: async () => {},
    onStatus: (s) => statuses.push(s),
    onEvent: () => {},
  });
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(calls, 1);
  assert.ok(statuses.includes('unauthorized'));
});

test('reports disabled on 404 (alerting turned off) and does not retry', async () => {
  const statuses = [];
  let calls = 0;
  connectAlertStream({
    url: '/x',
    getToken: () => 't',
    fetchImpl: async () => { calls += 1; return { ok: false, status: 404 }; },
    sleep: async () => {},
    onStatus: (s) => statuses.push(s),
    onEvent: () => {},
  });
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(calls, 1);
  assert.ok(statuses.includes('disabled'));
});
