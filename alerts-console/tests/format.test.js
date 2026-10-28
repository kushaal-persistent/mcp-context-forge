import test from 'node:test';
import assert from 'node:assert/strict';
import { parseUtc, relativeTime, allowedActions, buildListQuery, describeError, severityRank } from '../src/lib/format.js';

test('timestamps without a timezone are treated as UTC, not local time', () => {
  const naive = parseUtc('2026-10-28T10:00:00');
  const zoned = parseUtc('2026-10-28T10:00:00Z');
  assert.equal(naive.getTime(), zoned.getTime());
});

test('timestamps with an explicit offset are respected', () => {
  assert.equal(parseUtc('2026-10-28T12:00:00+02:00').getTime(), Date.parse('2026-10-28T10:00:00Z'));
});

test('invalid or empty timestamps give null / dash', () => {
  assert.equal(parseUtc(''), null);
  assert.equal(parseUtc('not a date'), null);
  assert.equal(relativeTime(null), '-');
});

test('relativeTime buckets', () => {
  const now = Date.parse('2026-10-28T10:00:00Z');
  assert.equal(relativeTime('2026-10-28T09:59:59Z', now), 'just now');
  assert.equal(relativeTime('2026-10-28T09:59:30Z', now), '30s ago');
  assert.equal(relativeTime('2026-10-28T09:45:00Z', now), '15m ago');
  assert.equal(relativeTime('2026-10-28T05:00:00Z', now), '5h ago');
  assert.equal(relativeTime('2026-10-20T10:00:00Z', now), '8d ago');
});

test('allowedActions follows the lifecycle', () => {
  assert.deepEqual(allowedActions({ status: 'open' }), { ack: true, resolve: true });
  assert.deepEqual(allowedActions({ status: 'acknowledged' }), { ack: false, resolve: true });
  assert.deepEqual(allowedActions({ status: 'resolved' }), { ack: false, resolve: false });
  assert.deepEqual(allowedActions({ status: 'expired' }), { ack: false, resolve: false });
});

test('buildListQuery drops empty filters and keeps paging', () => {
  assert.equal(buildListQuery({ page: 2, pageSize: 50 }), 'page=2&page_size=50');
  assert.equal(
    buildListQuery({ status: 'open', severity: 'HIGH', unread: true }),
    'status=open&severity=HIGH&unread=true&page=1&page_size=25'
  );
});

test('describeError handles strings, validation arrays and hints', () => {
  assert.equal(describeError(409, { detail: 'invalid transition' }), 'invalid transition');
  assert.equal(
    describeError(422, { detail: [{ loc: ['body', 'items', 0, 'channel'], msg: 'bad value' }] }),
    'items.0.channel: bad value'
  );
  assert.match(describeError(403, { detail: 'Password change required.', hint: 'Use the Admin UI.' }), /Use the Admin UI/);
  assert.equal(describeError(403, null), 'You do not have permission to do that.');
  assert.equal(describeError(500, null), 'Request failed (500)');
});

test('severityRank orders LOW < MEDIUM < HIGH < CRITICAL', () => {
  assert.ok(severityRank('LOW') < severityRank('MEDIUM'));
  assert.ok(severityRank('HIGH') < severityRank('CRITICAL'));
  assert.equal(severityRank('bogus'), -1);
});
