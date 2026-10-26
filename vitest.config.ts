import { defineConfig } from 'vitest/config';

// Only logic that does not need the WebView or Tauri (src/lib/*-rules.ts and the like) is tested
// here; screens are not. The security decisions live in Rust and are tested with `cargo test`.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    // No test file yet; keep `npm test` green until the first one is added.
    passWithNoTests: true,
  },
});
