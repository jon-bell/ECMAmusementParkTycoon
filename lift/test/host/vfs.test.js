'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Vfs, GAME_WIN } = require('../../host/vfs');

function tree() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vfs-'));
  const game = path.join(root, 'game'), cd = path.join(root, 'cd'), ov = path.join(root, 'ov');
  fs.mkdirSync(path.join(game, 'Data'), { recursive: true });
  fs.mkdirSync(path.join(game, 'Scenarios'), { recursive: true });
  fs.writeFileSync(path.join(game, 'Data', 'css1.dat'), 'abc');
  fs.writeFileSync(path.join(game, 'Data', 'game.cfg'), 'pristine');
  fs.mkdirSync(path.join(cd, 'Saved Games'), { recursive: true });
  return { root, v: new Vfs({ gameDir: game, cdDir: cd, overlayDir: ov }), game, ov };
}

test('paths: absolute, relative to the game directory, case-insensitive', () => {
  const { v, root } = tree();
  const r = v.resolve(GAME_WIN + '\\DATA\\CSS1.DAT');
  assert.deepStrictEqual(r.names.slice(3), ['Data', 'css1.dat']);
  assert.strictEqual(r.node.size, 3);
  assert.strictEqual(v.resolve('Data\\css1.dat').node.layer, 'pristine');
  assert.strictEqual(v.resolve('c:/program files/hasbro interactive/rollercoaster tycoon/data/../Data/./CSS1.dat').node.size, 3);
  assert.strictEqual(v.resolve('D:\\Saved Games').node.isDir, true);
  const miss = v.resolve('Data\\nope.dat');
  assert.strictEqual(miss.node, null); assert.strictEqual(miss.parentOk, true);
  assert.strictEqual(v.resolve('Nodir\\nope.dat').parentOk, false);
  assert.strictEqual(v.resolve('C:\\Windows\\x').node, null);
  fs.rmSync(root, { recursive: true });
});

test('overlay takes precedence and keeps the pristine install unchanged', () => {
  const { v, root, game, ov } = tree();
  const r = v.resolve('Data\\GAME.CFG');
  assert.ok(v.inGameDir(r.drive, r.names));
  v.ensureOverlayParents(r.names);
  fs.writeFileSync(v.overlayPath(r.names), 'written');
  assert.strictEqual(fs.readFileSync(path.join(game, 'Data', 'game.cfg'), 'utf8'), 'pristine');
  const r2 = v.resolve('data\\game.cfg');
  assert.strictEqual(r2.node.layer, 'overlay');
  assert.strictEqual(fs.readFileSync(r2.node.host, 'utf8'), 'written');
  assert.ok(fs.existsSync(path.join(ov, 'Data', 'game.cfg')));
  const names = v.list('C', r.names.slice(0, 4)).map((e) => e.name).sort();
  assert.deepStrictEqual(names, ['.', '..', 'css1.dat', 'game.cfg']);
  fs.rmSync(root, { recursive: true });
});
