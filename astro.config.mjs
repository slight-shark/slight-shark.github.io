// @ts-check
import { defineConfig } from 'astro/config';

import react from '@astrojs/react';
import tailwind from '@astrojs/tailwind';

import yaml from "@rollup/plugin-yaml";

// https://astro.build/config
export default defineConfig({
  integrations: [react(), tailwind()],
  vite: {
    plugins: [yaml()]
  }
});
