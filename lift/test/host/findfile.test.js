'use strict';
const test = require('node:test');
const assert = require('node:assert');
const ff = require('../../host/findfile');

test('Wine short names', () => {
  assert.strictEqual(ff.hashShortName('Saved Games'), 'SAVE~YWG');   // observed in the oracle's hook.log
  assert.strictEqual(ff.isLegal8dot3('css1.dat'), true);              // hook.log: "css1.dat []"
  assert.strictEqual(ff.isLegal8dot3('sc0.SC4'), true);
  assert.strictEqual(ff.isLegal8dot3('Saved Games'), false);
  assert.strictEqual(ff.isLegal8dot3('ABCDEFGHI'), false);
  assert.strictEqual(ff.isLegal8dot3('A.BCDE'), false);
  assert.strictEqual(ff.isLegal8dot3('A~1'), false);
  assert.strictEqual(ff.isLegal8dot3('..'), true);
  assert.match(ff.hashShortName('Big 90.TD4'), /^BIG_~[A-Z0-5]{3}\.TD4$/);
});

test('CD alias rule (rcthook.c cd_alias)', () => {
  assert.strictEqual(ff.cdAlias('Saved Games', 'SAVE~YWG'), 'SAVED~1');
  assert.strictEqual(ff.cdAlias('Scenarios', ''), '');
  assert.strictEqual(ff.cdAlias('a.b c.defgh', 'X'), 'ABCDE~1');
  assert.strictEqual(ff.cdAlias('Saved Games', 'SAVE~YWG')[5], '~');
});

test('Wine mask matching', () => {
  assert.ok(ff.matchMask('sc6.sc4', '*.SC4'));
  assert.ok(!ff.matchMask('SC.IDX', '*.SC4'));
  assert.ok(!ff.matchMask('.', '*.SC4'));
  assert.ok(ff.matchMask('noext', '*.*'));
  assert.ok(ff.matchMask('a.b.c', '*.c'));
  assert.ok(ff.matchMask('abc', 'a?c'));
  assert.ok(!ff.matchMask('abcd', 'a?c'));
  assert.ok(ff.matchMask('abc', 'abc.'));
  assert.ok(ff.matchMask('xaxb', '*a*b'));
});

test('find set: matching, strcmp order, attributes, CD aliases', () => {
  const listing = [
    { name: '.', isDir: true, size: 0, writable: true }, { name: '..', isDir: true, size: 0, writable: true },
    { name: 'sc6.sc4', isDir: false, size: 10, writable: true }, { name: 'SC10.SC4', isDir: false, size: 5, writable: true },
    { name: 'sc0.SC4', isDir: false, size: 7, writable: false }, { name: 'SC.IDX', isDir: false, size: 1, writable: true },
  ];
  const s = ff.buildFindSet(listing, '*.SC4', false);
  assert.deepStrictEqual(s.map((e) => e.name), ['SC10.SC4', 'sc0.SC4', 'sc6.sc4']);
  assert.deepStrictEqual(s.map((e) => e.attr), [0x20, 0x21, 0x20]);
  const one = ff.buildFindSet([{ name: 'css1.dat', isDir: false, size: 3, writable: true }], 'CSS1.DAT', false);
  assert.deepStrictEqual(one.map((e) => [e.name, e.alt]), [['css1.dat', '']]);
  const cd = ff.buildFindSet([{ name: 'Saved Games', isDir: true, size: 4096, writable: true }], 'Saved Games', true);
  assert.deepStrictEqual(cd, [{ attr: 0x10, sizeLow: 0, sizeHigh: 0, name: 'Saved Games', alt: 'SAVED~1' }]);
});

test('put_find leaves the caller buffer tail untouched', () => {
  const buf = new Uint8Array(400).fill(0xCC);
  const mem = {
    w32: (a, v) => { for (let i = 0; i < 4; i++) buf[a + i] = (v >>> (8 * i)) & 255; },
    wstr: (a, s) => { for (let i = 0; i < s.length; i++) buf[a + i] = s.charCodeAt(i); buf[a + s.length] = 0; },
  };
  ff.putFind(mem, 0, { attr: 0x20, sizeLow: 9, sizeHigh: 0, name: 'ab', alt: '' });
  assert.deepStrictEqual([...buf.subarray(44, 48)], [0x61, 0x62, 0, 0xCC]);
  assert.deepStrictEqual([...buf.subarray(304, 306)], [0, 0xCC]);
  assert.deepStrictEqual([...buf.subarray(4, 12)], [0x00, 0x80, 0x2d, 0x5c, 0x9b, 0x5d, 0xbf, 0x01]);
  assert.strictEqual(buf[318], 0xCC);
});
