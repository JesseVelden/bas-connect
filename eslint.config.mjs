// @ts-check

import eslint from '@eslint/js';
import stylistic from '@stylistic/eslint-plugin';
import simpleImportSort from 'eslint-plugin-simple-import-sort';
import tseslint from 'typescript-eslint';

export default tseslint.config(
	eslint.configs.recommended,
	tseslint.configs.recommended,
	{
		plugins: {
			'@stylistic': stylistic,
			'simple-import-sort': simpleImportSort,

		},
		rules: {
			'@stylistic/indent': ['error', 'tab'], 
			'@stylistic/quotes': ['error', 'single', { 'avoidEscape': true, 'allowTemplateLiterals': true }],
			'@stylistic/object-curly-spacing': ['error', 'always'],
			'@stylistic/semi': ['error', 'always'],
			'@stylistic/comma-dangle': ['error', 'always-multiline'],
			'@stylistic/key-spacing': ['error', { 'afterColon': true }],
			'@stylistic/arrow-spacing': ['error', { 'before': true, 'after': true }],
			'@stylistic/keyword-spacing': ['error', { 'after': true }],
			'@stylistic/space-in-parens': ['error', 'never'],
			'@stylistic/space-infix-ops': ['error'],
			'@stylistic/no-multi-spaces': ['error'],

			'@typescript-eslint/no-explicit-any': 'warn',
			'@typescript-eslint/no-unused-vars': ['warn', {
				'argsIgnorePattern': '^_',
				'caughtErrorsIgnorePattern': '^_',
				'destructuredArrayIgnorePattern': '^_',
				'varsIgnorePattern': '^_',
			}],

			'simple-import-sort/imports': 'error',
			'simple-import-sort/exports': 'error',
		},
	},
);
