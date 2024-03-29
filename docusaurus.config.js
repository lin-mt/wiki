// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const lightCodeTheme = require('prism-react-renderer/themes/github');
const darkCodeTheme = require('prism-react-renderer/themes/dracula');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'lin-mt',
  tagline: 'Enjoy the quiet.',
  favicon: 'img/favicon.ico',

  // Set the production url of your site here
  url: 'https://lin-mt.github.io/',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/wiki/',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'lin-mt', // Usually your GitHub org/user name.
  projectName: 'wiki', // Usually your repo name.
  trailingSlash: false,

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  // Even if you don't use internalization, you can use this field to set useful
  // metadata like html lang. For example, if your site is Chinese, you may want
  // to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'zh-Hans',
    locales: ['zh-Hans'],
  },
  markdown: {
    mermaid: true,
  },
  themes: ['@docusaurus/theme-mermaid'],
  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          editUrl: 'https://github.com/lin-mt/wiki/tree/main/',
        },
        blog: {
          showReadingTime: true,
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl: 'https://github.com/lin-mt/wiki/tree/main/',
        },
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],

  themeConfig:
  /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      // Replace with your project's social card
      image: 'img/docusaurus-social-card.jpg',
      navbar: {
        title: 'lin-mt',
        logo: {
          alt: 'lin-mt',
          src: 'img/logo.svg',
        },
        items: [
          {
            position: 'left',
            label: '🤫 Quiet',
            items: [
              {
                type: 'docSidebar',
                sidebarId: 'quietDocument',
                label: '📄 文档',
              },
              {
                type: 'docSidebar',
                sidebarId: 'quietPlugins',
                label: '🧰 插件',
              },
            ]
          },
          {
            label: '🔧 解决方案',
            position: 'right',
            items: [
              {
                type: 'docSidebar',
                sidebarId: 'solutionQuiet',
                label: '🤫 Quiet'
              }
            ]
          },
          {to: '/blog', label: '📕博客', position: 'right'},
          {
            href: 'https://github.com/lin-mt/',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        copyright: `Copyright © ${new Date().getFullYear()} lin-mt, Inc. Built with Docusaurus.`,
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
        additionalLanguages: ["kotlin", "java", "scala"],
      },
      algolia: {
        // The application ID provided by Algolia
        appId: 'SM4ZQXO5BK',
        // Public API key: it is safe to commit it
        apiKey: 'de5cb8611d8c6a0eecb50a6e635a7290',
        indexName: 'linmtwiki',
      },
    }),

};

module.exports = config;
