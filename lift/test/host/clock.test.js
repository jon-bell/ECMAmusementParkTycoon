'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { VirtualClock, VT_BASE } = require('../../host/clock');

test('query returns then advances by the quantum; Sleep advances', () => {
  const c = new VirtualClock(VT_BASE, 1);
  assert.strictEqual(c.query(), 5000000);
  assert.strictEqual(c.query(), 5000001);
  c.sleep(10);
  assert.strictEqual(c.query(), 5000012);
  const q = new VirtualClock(0xFFFFFFFF, 3);
  assert.strictEqual(q.query(), 0xFFFFFFFF);
  assert.strictEqual(q.query(), 2);
});

test('GetSystemTime = 2000-01-13 12:00 + uint32(vt - 5000000) ms', () => {
  assert.deepStrictEqual(new VirtualClock(5000000).systemTime(),
    { wYear: 2000, wMonth: 1, wDayOfWeek: 4, wDay: 13, wHour: 12, wMinute: 0, wSecond: 0, wMilliseconds: 0 });
  assert.deepStrictEqual(new VirtualClock(7000000 + 1234).systemTime(),
    { wYear: 2000, wMonth: 1, wDayOfWeek: 4, wDay: 13, wHour: 12, wMinute: 33, wSecond: 21, wMilliseconds: 234 });
  // a seed below the base wraps: + (2^32 - 1) ms = 49 d 17:02:47.295
  assert.deepStrictEqual(new VirtualClock(4999999).systemTime(),
    { wYear: 2000, wMonth: 3, wDayOfWeek: 5, wDay: 3, wHour: 5, wMinute: 2, wSecond: 47, wMilliseconds: 295 });
});
