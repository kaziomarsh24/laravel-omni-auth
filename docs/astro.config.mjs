// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	site: 'https://kaziomarsh24.github.io',
	base: '/laravel-omni-auth',
	integrations: [
		starlight({
			head: [
				{
					tag: 'script',
					attrs: {
						type: 'module',
						src: '/laravel-omni-auth/mermaid-init.js',
					},
				},
				{
					tag: 'meta',
					attrs: {
						property: 'og:image',
						content: 'https://kaziomarsh24.github.io/laravel-omni-auth/og-image.png',
					},
				},
				{
					tag: 'meta',
					attrs: {
						name: 'twitter:image',
						content: 'https://kaziomarsh24.github.io/laravel-omni-auth/og-image.png',
					},
				},
				{
					tag: 'meta',
					attrs: {
						name: 'twitter:card',
						content: 'summary_large_image',
					},
				},
			],
			title: 'Laravel OmniAuth',
			logo: {
				src: './src/assets/logo.svg',
				replacesTitle: false,
			},
			customCss: ['./src/styles/custom.css'],
			description: 'Production-grade, battle-tested authentication package for Laravel web and mobile applications.',
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/kaziomarsh24/laravel-omni-auth' },
			],
			sidebar: [
				{
					label: 'Getting Started',
					items: [
						{ label: 'Overview', slug: 'getting-started/overview' },
						{ label: 'Why OmniAuth?', slug: 'getting-started/why-omniauth' },
						{ label: 'Installation', slug: 'getting-started/installation' },
						{ label: 'Configuration', slug: 'getting-started/configuration' },
					],
				},
				{
					label: 'Extensibility & Headless',
					items: [
						{ label: 'Headless Mode & Facades', slug: 'getting-started/customization' },
					],
				},
				{
					label: 'Security & Architecture',
					items: [
						{ label: 'Dual-Mode Authentication', slug: 'architecture/dual-mode-tokens' },
						{ label: 'Token Rotation & Device Tracking', slug: 'architecture/token-rotation' },
						{ label: 'Security Defenses', slug: 'architecture/security-defenses' },
					],
				},
				{
					label: 'Feature Guides',
					items: [
						{ label: 'Two-Factor Authentication', slug: 'features/two-factor-auth' },
						{ label: 'Social Login & Native Tokens', slug: 'features/social-login' },
						{ label: 'Device Management', slug: 'features/device-management' },
						{ label: 'Passwordless Magic Links', slug: 'features/magic-links' },
						{ label: 'Verification & Account Deletion', slug: 'features/verification-and-deletion' },
					],
				},
				{
					label: 'Client Integration',
					items: [
						{ label: 'Next.js & Web SPA', slug: 'clients/nextjs-web' },
						{ label: 'Flutter Mobile', slug: 'clients/flutter-mobile' },
						{ label: 'React Native & Expo', slug: 'clients/react-native-expo' },
					],
				},
				{
					label: 'API Reference',
					items: [
						{ label: 'Complete API Reference (29 Endpoints)', slug: 'reference/api-reference' },
					],
				},
			],
		}),
	],
});
