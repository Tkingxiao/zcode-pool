// 构建后把 NSIS 安装包拷到 release/：tauri 的产物目录固定在 src-tauri/target/，改不了，只能复制。
// 用法：npm run tauri:build（构建 + 拷贝一条龙），或单独 node scripts/copy-installer.mjs。
import { copyFileSync, mkdirSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const srcDir = join(root, "src-tauri", "target", "release", "bundle", "nsis");
const outDir = join(root, "release");

const exes = readdirSync(srcDir).filter((f) => f.endsWith(".exe"));
if (exes.length === 0) {
  console.error(`[copy-installer] ${srcDir} 里没有安装包 —— 先跑 npm run tauri:build`);
  process.exit(1);
}
// 多个就取最新的：历史版本留在 bundle 目录里，release/ 只放当前这一份
const newest = exes
  .map((f) => ({ f, t: statSync(join(srcDir, f)).mtimeMs }))
  .sort((a, b) => b.t - a.t)[0].f;

mkdirSync(outDir, { recursive: true });
const from = join(srcDir, newest);
const to = join(outDir, newest);
copyFileSync(from, to);
console.log(`[copy-installer] ${from} -> ${to}`);
