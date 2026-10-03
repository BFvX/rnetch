import { spawn } from 'node:child_process';
import process from 'node:process';
import electron from 'electron';
import { createServer } from 'vite';

const server = await createServer({
  configFile: 'vite.config.js'
});

await server.listen();

const viteUrl = server.resolvedUrls?.local?.[0] ?? 'http://127.0.0.1:5173/';
console.log(`Renderer dev server: ${viteUrl}`);

const child = spawn(electron, ['.'], {
  stdio: 'inherit',
  env: {
    ...process.env,
    VITE_DEV_SERVER_URL: viteUrl
  }
});

const shutdown = async (exitCode = 0) => {
  child.kill();
  await server.close();
  process.exit(exitCode);
};

child.on('exit', async (code) => {
  await server.close();
  process.exit(code ?? 0);
});

process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));
