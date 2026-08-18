import { useRef, useState } from "react";
import gsap from "gsap";

import Navbar from "./components/Navbar";

import Overview from "./sections/Overview";
import Threats from "./sections/Threats";
import Graph from "./sections/Graph";
import Alerts from "./sections/Alerts";
import Analytics from "./sections/Analytics";

const sections = [
  "Overview",
  "Threats",
  "Graph",
  "Alerts",
  "Analytics",
];

function App() {
  const worldRef = useRef<HTMLElement>(null);

  const [activeSection, setActiveSection] =
    useState("Overview");

  const navigateTo = (section: string) => {
    const targetIndex = sections.indexOf(section);

    if (
      targetIndex === -1 ||
      !worldRef.current
    ) {
      return;
    }

    const targetX =
      -(targetIndex * window.innerWidth);

    gsap.killTweensOf(worldRef.current);

    gsap.to(worldRef.current, {
      x: targetX,
      duration: 1.15,
      ease: "power3.inOut",
    });

    setActiveSection(section);
  };

  return (
    <div className="app">

      <Navbar
        activeSection={activeSection}
        onNavigate={navigateTo}
      />

      <main
        ref={worldRef}
        className="horizontal-world"
      >
        <Overview />
        <Threats />
        <Graph />
        <Alerts />
        <Analytics />
      </main>

    </div>
  );
}

export default App;