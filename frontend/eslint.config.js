import globals from 'globals';
import js from '@eslint/js';
import react from 'eslint-plugin-react';

export default [
  { ignores: ['dist'] },
  js.configs.recommended,
  {
    files: ['**/*.jsx', '**/*.js'],
    plugins: { react },
    languageOptions: {
      globals: { ...globals.browser },
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    settings: { react: { version: 'detect' } },
    rules: { 'react/react-in-jsx-scope': 'off', 'react/jsx-uses-vars': 'error' },
  },
];
