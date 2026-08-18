interface NavbarProps {
  activeSection: string;
  onNavigate: (section: string) => void;
}

const navItems = [
  "Overview",
  "Threats",
  "Graph",
  "Alerts",
  "Analytics",
];

function Navbar({
  activeSection,
  onNavigate,
}: NavbarProps) {
  return (
    <nav className="navbar">
      <div className="logo">
        <div className="logo-icon">◈</div>

        <span>SENTINEL</span>
      </div>

      <div className="nav-links">
        {navItems.map((item) => (
          <button
            key={item}
            className={`nav-link ${
              activeSection === item ? "active" : ""
            }`}
            onClick={() => onNavigate(item)}
          >
            {item.toUpperCase()}
          </button>
        ))}
      </div>

      <div className="system-status">
        <span className="status-dot"></span>
        <span>LIVE</span>
      </div>
    </nav>
  );
}

export default Navbar;