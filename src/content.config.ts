import { defineCollection, z } from "astro:content"
import { glob } from "astro/loaders"

const writeups = defineCollection({
  loader: glob({
    pattern: "**/*.{md,mdx}",
    base: "./src/content/writeups"
  }),
  schema: z.object({
    title: z.string(),
    date: z.coerce.date(),
    authors: z.array(z.string()),
  })
})

export const collections = { writeups }
