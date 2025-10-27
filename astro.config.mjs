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
import rehypeMathjax from 'rehype-mathjax';

import rehypeKatex from 'rehype-katex';
import 'katex/dist/katex.min.css';

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
      rehypeKatex // <- supports inline and display math automatically
    ]
  }
});
