import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/unit/**/*.test.ts', 'test/api/**/*.test.ts'],
    testTimeout: 30_000,
    hookTimeout: 30_000,
    // Tests use isolated in-memory SQLite databases; run files in parallel, tests within a file sequentially.
    fileParallelism: true,
  },
});
