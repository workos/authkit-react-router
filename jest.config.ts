import type { Config } from 'jest';
import { buildSync } from 'esbuild';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// react-router 8 is ESM-only and Jest's CommonJS runtime can't require() it, so
// tests get a CJS bundle of it. v7 ships CJS and is used as-is.
// shortcut: bundles react-router for tests, drop once the suite runs as native ESM (e.g. Vitest).
function reactRouterModuleMapper(): Record<string, string> {
  const { version } = JSON.parse(readFileSync(join(__dirname, 'node_modules/react-router/package.json'), 'utf8'));
  if (Number(version.split('.')[0]) < 8) {
    return {};
  }

  const outfile = join(__dirname, 'node_modules/.cache/authkit-react-router/react-router.cjs');
  buildSync({
    entryPoints: [require.resolve('react-router')],
    outfile,
    bundle: true,
    platform: 'node',
    format: 'cjs',
    external: ['react', 'react-dom'],
    logLevel: 'warning',
  });
  return { '^react-router$': outfile };
}

const reactRouterMapper = reactRouterModuleMapper();

const config: Config = {
  // Automatically clear mock calls, instances, contexts and results before every test
  clearMocks: true,

  // Automatically reset mock state between every test
  resetMocks: true,

  // Indicates whether the coverage information should be collected while executing the test
  collectCoverage: true,

  // The directory where Jest should output its coverage files
  coverageDirectory: 'coverage',

  collectCoverageFrom: ['src/**/*.{ts,tsx}', '!src/**/*.spec.{ts,tsx}', '!src/test-utils/**'],

  // Indicates which provider should be used to instrument code for coverage
  coverageProvider: 'babel',

  // A map from regular expressions to module names or to arrays of module names that allow to stub out resources with a single module
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1', // Handle ESM imports
  },

  // A preset that is used as a base for Jest's configuration
  preset: 'ts-jest',

  // Run tests from one or more projects
  projects: [
    {
      displayName: 'jsdom',
      testEnvironment: 'jsdom',
      testMatch: ['**/*.spec.tsx', '**/__tests__/**/*.spec.tsx'],
      transform: {
        '^.+\\.tsx?$': 'ts-jest', // Use ts-jest for TypeScript files
      },
      moduleNameMapper: {
        '^(\\.{1,2}/.*)\\.js$': '$1',
        ...reactRouterMapper,
      },
    },
    {
      displayName: 'node',
      testEnvironment: 'node',
      testMatch: ['**/*.spec.ts', '**/__tests__/**/*.spec.ts'],
      transform: {
        '^.+\\.tsx?$': 'ts-jest',
      },
      moduleNameMapper: {
        '^(\\.{1,2}/.*)\\.js$': '$1',
        ...reactRouterMapper,
      },
      setupFiles: ['<rootDir>/jest.setup.ts'],
    },
  ],

  // Indicates whether each individual test should be reported during the run
  verbose: true,

  // Optionally, add these for better TypeScript support
  extensionsToTreatAsEsm: ['.ts'],

  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
};

export default config;
