import { useState } from "react";
import slightSmileFace from "../assets/slight_smile_face.svg";

export default function Navbar() {
  const url = window.location.pathname;
  const [menuShown, showMenu] = useState(false);

  return (
    <div className="h-[5rem] flex items-center justify-between text-lg">
      <div className="h-full relative flex justify-start items-center">
        <div className="ml-6 flex items-center justify-center gap-5 text-app-yellow">
          <img
            src={slightSmileFace.src}
            alt="menu"
            className="h-[3rem] aspect-square rounded-full bg-app-yellow"
          />
          <span className="cursor-pointer" onClick={() => showMenu(true)}>
            menu
          </span>
        </div>
        <div className={(menuShown ? "" : "-translate-x-full") + " " + "box-border w-[100vw] lg:w-[40vw] absolute top-0 left-0 h-full rounded-r-full bg-app-yellow transition-all flex px-6 items-center justify-start gap-8 text-black z-10"}>
          <img
            src={slightSmileFace.src}
            alt="menu"
            className="hidden sm:block h-[3rem] aspect-square rounded-full bg-app-yellow"
          />
          <div>
            <a className={"navbar-link" + (url === "/members" ? " active" : "")} href="/members">
              members
            </a>
          </div>
          <div>
            <a className={"navbar-link" + (url === "/writeups" ? " active" : "")} href="/writeups">
              writeups
            </a>
          </div>
          <div>
            <a className={"navbar-link" + (url === "/blog" ? " active" : "")} href="/blog">
              blog
            </a>
          </div>
          <div className="ml-auto cursor-pointer">
            <i className="fa-solid fa-x" onClick={() => showMenu(false)} />
          </div>
        </div>
      </div>
      <div className="h-full w-1/4 relative flex justify-end items-center">
        <i className="fa-regular fa-magnifying-glass bg-app-purple rounded-full aspect-square p-[1rem] mr-6">
        </i>
      </div>
    </div>
  )
}
