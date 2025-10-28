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

import remarkMath from 'remark-math';
import rehypeMathjaxChtml from 'rehype-mathjax/chtml'

export default defineConfig({
  integrations: [react(), tailwind(), mdx()],
  vite: { plugins: [yaml()] },
  markdown: {
    syntaxHighlight: false,
    shikiConfig: { wrap: true },
    remarkPlugins: [remarkEmoji, remarkMath],
    rehypePlugins: [
      sectionize,
      rehypeFigure,
      [
        rehypePrettyCode,
        { theme: "kanagawa-wave", defaultLang: "ansi" }
      ],
      [rehypeMathjaxChtml, {
        chtml: {
          fontURL: 'https://cdn.jsdelivr.net/npm/mathjax@3/es5/output/chtml/fonts/woff-v2'
        }
      }], // to fix inline not rendering correctly. ref: https://github.com/vercel/next.js/discussions/74625
    ]
  }
});
