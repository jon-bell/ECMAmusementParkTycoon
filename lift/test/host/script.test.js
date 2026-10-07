'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { parseScript, strtoul, ScriptError, A, W_TICK, W_FRAME } = require('../../host/script');

test('strtoul(…, 0) as mingw/msvcrt', () => {
  assert.strictEqual(strtoul('0x100'), 256);
  assert.strictEqual(strtoul('0X1f'), 31);
  assert.strictEqual(strtoul('010'), 8);
  assert.strictEqual(strtoul('08'), 0);
  assert.strictEqual(strtoul('0x'), 0);
  assert.strictEqual(strtoul('12abc'), 12);
  assert.strictEqual(strtoul('-1'), 0xFFFFFFFF);
  assert.strictEqual(strtoul('+7'), 7);
  assert.strictEqual(strtoul('99999999999'), 0xFFFFFFFF);
  assert.strictEqual(strtoul('-99999999999'), 0xFFFFFFFF);
  assert.strictEqual(strtoul('x'), 0);
  assert.strictEqual(strtoul('4294967295'), 0xFFFFFFFF);
});

test('public corpus scripts parse as the oracle parses them', () => {
  const dir = path.join(__dirname, '../../../corpus/public');
  for (const f of fs.readdirSync(dir)) {
    const s = parseScript(fs.readFileSync(path.join(dir, f), 'latin1'));
    assert.ok(s.actions.length > 0, f);
  }
  const s = parseScript(fs.readFileSync(path.join(dir, 'diamond-heights-pause.txt'), 'latin1'));
  assert.strictEqual(s.seed, 7000000);
  assert.deepStrictEqual(s.actions.map((a) => [a.whenKind, a.when, a.rel, a.action, a.line]), [
    [W_FRAME, 1, false, A.LOAD, 3], [W_TICK, 1, false, A.CMD, 4], [W_TICK, 1000, false, A.CMD, 5],
    [W_FRAME, 1200, true, A.CMD, 6], [W_TICK, 3000, false, A.QUIT, 7]]);
  assert.strictEqual(s.actions[1].arg, 33);
  assert.strictEqual(s.actions[1].r.ebx, 1);
  assert.strictEqual(s.actions[1].r.edx, 0x100);
  assert.strictEqual(s.actions[0].arg, 3);
});

test('all actions and register syntax', () => {
  const s = parseScript([
    'frame 5 call 0x401000 eax=1 ebx=2 ecx=3 edx=4 esi=5 edi=6 ebp=7 esp=8 eflags=9 bogus=1 noeq',
    'tick 2 key 30 1', 'tick 3 cursor 10 20', 'tick 4 mouse 1 2 3', 'tick 5 poke 0x5F4000 0xff',
    'tick 6 dump', 'tick 7 shot', 'tick 8 fb', '\ttick\t9\tquit\t# comment', '# only comment', '',
  ].join('\n'));
  const [c, k, cu, mo, po] = s.actions;
  assert.deepStrictEqual(c.r, { edi: 6, esi: 5, ebp: 7, esp: 8, ebx: 2, edx: 4, ecx: 3, eax: 1, eflags: 9 });
  assert.strictEqual(c.action, A.CALL); assert.strictEqual(c.arg, 0x401000);
  assert.deepStrictEqual([k.arg, k.arg2], [30, 1]);
  assert.deepStrictEqual([cu.arg, cu.arg2], [10, 20]);
  assert.deepStrictEqual([mo.arg, mo.arg2, mo.r.eax], [1, 2, 3]);
  assert.deepStrictEqual([po.arg, po.arg2], [0x5F4000, 0xff]);
  assert.deepStrictEqual(s.actions.slice(5).map((a) => a.action), [A.DUMP, A.SHOT, A.FB, A.QUIT]);
});

test('fatal conditions', () => {
  const bad = (t, why, line) => assert.throws(() => parseScript(t), (e) => e instanceof ScriptError && e.why === why && e.line === line);
  bad('\nframe 1\n', 'action too short', 2);
  bad('seed\n', 'action too short', 1);
  bad('at 1 quit\n', "time must be 'tick N' or 'frame [+]N'", 1);
  bad('frame 1 load\n', 'unknown action or missing arguments', 1);
  bad('frame 1 key 1\n', 'unknown action or missing arguments', 1);
  bad('frame 1 mouse 1 2\n', 'unknown action or missing arguments', 1);
  bad('frame 1 jump 1\n', 'unknown action or missing arguments', 1);
});
