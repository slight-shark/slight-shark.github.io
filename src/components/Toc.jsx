import { useEffect, useRef } from "react"

export default function Toc({ headings }) {
  const tocRef = useRef(null)
  useEffect(() => {
    const markdownBody = document.getElementsByClassName("markdown-body")[0]

    const onElementObserved = (entries) => {
      entries.forEach(({ target, isIntersecting }) => {
        // get the actual heading from the section element
        const heading = target.querySelector("h1, h2, h3, h4, h5, h6")
        if (heading) {
          const id = heading.getAttribute("id")
          const link = tocRef.current.querySelector(`div[data-id="${id}"]`)
          if (link) {
            if (isIntersecting) {
              link.className = "text-app-yellow"
            } else {
              link.className = "text-white"
            }
          }
        }
      })
    }

    const observer = new IntersectionObserver(onElementObserved, {
      rootMargin: "-150px 0px -60px 0px"
    })

    markdownBody
      .querySelectorAll("section")
      .forEach((section) => observer.observe(section)
      )
  }, [tocRef])

  return (
    <div className="hidden md:block mt-[4rem] sticky top-24 text-xl">
      <div className="text-white opacity-80 mb-4">Sections</div>
      <div ref={tocRef}>
        {headings.map(h => (
          <div data-id={h.slug} key={h.slug}>
            <a href={"#" + h.slug}>{h.text}</a>
          </div>
        ))}
      </div>
    </div>
  )
}
