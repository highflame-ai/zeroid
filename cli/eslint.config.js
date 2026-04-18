import tseslint from "typescript-eslint";

export default tseslint.config(
  ...tseslint.configs.recommended,
  {
    rules: {
      // Allow explicit `any` in tests and when interfacing with Commander (opts: unknown)
      "@typescript-eslint/no-explicit-any": "warn",
      // Allow non-null assertion — used in decode.ts with a length guard above
      "@typescript-eslint/no-non-null-assertion": "off",
      // Require type annotations on exported functions but not internal helpers
      "@typescript-eslint/explicit-function-return-type": "off",
      "@typescript-eslint/explicit-module-boundary-types": "off",
      // These are useful but too noisy for a CLI that casts Commander opts
      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
    },
  },
  {
    // Relax rules further in test files
    files: ["tests/**/*.ts"],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
    },
  },
  {
    ignores: ["dist/**", "node_modules/**"],
  },
);
