import { cpSync, rmSync, mkdirSync, readdirSync } from 'node:fs';

rmSync('dist', { recursive: true, force: true });
mkdirSync('dist');
for (const f of readdirSync('.')) {
  if (/\.(html|png|jpg|svg|ico|css|js)$/i.test(f) && f !== 'build.mjs') cpSync(f, `dist/${f}`);
}
console.log('Build selesai -> dist/');
