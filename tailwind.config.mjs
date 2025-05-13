/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  theme: {
    extend: {
      colors: {
        black: '#06070a',
        'app-yellow': '#FFC01D',
        'app-purple': '#7231FF',
      },
    },
  },
  plugins: [],
};
