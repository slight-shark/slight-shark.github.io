// @ts-check
import { defineConfig } from 'astro/config';

import react from '@astrojs/react';
import tailwind from '@astrojs/tailwind';
import mdx from "@astrojs/mdx"

import yaml from "@rollup/plugin-yaml";
import sectionize from "@hbsnow/rehype-sectionize"
import { rehypePrettyCode } from "rehype-pretty-code"
import remarkEmoji from "remark-emoji"
import rehypeFigure from "@microflash/rehype-figure"

// https://astro.build/config
export default defineConfig({
  integrations: [react(), tailwind(), mdx()],
  vite: {
    plugins: [yaml()]
  },
  markdown: {
    syntaxHighlight: false,
    shikiConfig: {
      wrap: true
    },

    remarkPlugins: [
      remarkEmoji
    ],

    rehypePlugins: [
      sectionize,
      rehypeFigure,
      [
        rehypePrettyCode,
        {
          theme: "kanagawa-wave",
          defaultLang: "ansi",
        }
      ]
    ]
  }
});
