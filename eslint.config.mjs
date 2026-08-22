import js from "@eslint/js";

export default [
  js.configs.recommended,
  {
    files: ["docs/js/**/*.mjs", "test/**/*.mjs"],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "module",
      globals: {
        // browser + node WebCrypto surface used by the demos and tests
        globalThis: "readonly", crypto: "readonly", TextEncoder: "readonly", TextDecoder: "readonly",
        document: "readonly", window: "readonly", addEventListener: "readonly", setTimeout: "readonly",
        ImageData: "readonly", console: "readonly",
      },
    },
    rules: {
      "no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "no-undef": "error",
    },
  },
  { ignores: ["node_modules/", "docs/diagrams/", "reviews/", "scripts/"] },
];
