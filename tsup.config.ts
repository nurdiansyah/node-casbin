import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/client.ts'],
  dts: {
    entry: ['src/index.ts', 'src/client.ts'],
  },
  outDir: 'libs',
  format: ['esm'],
  treeshake: "smallest",
  clean: true,
});
