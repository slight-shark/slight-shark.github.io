// @ts-check
import { defineConfig } from 'astro/config';

import react from '@astrojs/react';
import tailwind from '@astrojs/tailwind';
import mdx from "@astrojs/mdx"

import yaml from "@rollup/plugin-yaml";
import sectionize from "@hbsnow/rehype-sectionize"

// https://astro.build/config
export default defineConfig({
  integrations: [react(), tailwind(), mdx()],
  vite: {
    plugins: [yaml()]
  },
  markdown: {
    rehypePlugins: [
      sectionize
    ]
  }
});
