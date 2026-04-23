import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/passport/canonical.ts', 'src/passport/reasons.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  target: 'es2022',
  outDir: 'dist',
});
