import { defineConfig } from "tsup";

export default defineConfig([
  // Core build
  {
    entry: ["src/index.ts"],
    format: ["esm"],
    dts: true,
    clean: true,
    sourcemap: true,
    minify: false,
    splitting: false,
    treeshake: true,
    target: "es2022",
  },
  // Session module - framework-agnostic, server-side only
  {
    entry: ["src/session/index.ts"],
    format: ["esm"],
    dts: true,
    outDir: "dist/session",
    sourcemap: true,
    minify: false,
    splitting: false,
    treeshake: true,
    target: "es2022",
  },
  // Qwik adapter - MUST externalize core and Qwik to avoid duplication
  {
    entry: ["src/qwik/index.tsx"],
    format: ["esm"],
    dts: true,
    outDir: "dist/qwik",
    sourcemap: true,
    minify: false,
    splitting: false,
    treeshake: true,
    target: "es2022",
    external: [
      "@builder.io/qwik",
      "@builder.io/qwik/jsx-runtime",
      "@douvery/auth",
      "@douvery/auth/session",
    ],
    tsconfig: "tsconfig.qwik.json",
  },
  // React adapter - MUST externalize core and React to avoid duplication
  {
    entry: ["src/react/index.tsx"],
    format: ["esm"],
    dts: true,
    outDir: "dist/react",
    sourcemap: true,
    minify: false,
    splitting: false,
    treeshake: true,
    target: "es2022",
    external: ["react", "@douvery/auth"],
    tsconfig: "tsconfig.react.json",
  },
]);
