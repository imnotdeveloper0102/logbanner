import { NavLink } from 'react-router-dom';
import { useAuth } from '../auth';

export default function Topbar() {
  const { user, logout } = useAuth();
  return (
    <header className="topbar">
      <span className="brand">logbanner</span>
      <nav className="topbar-nav" aria-label="Sections">
        <NavLink to="/" end className={({ isActive }) => (isActive ? 'nav-active' : '')}>
          Overview
        </NavLink>
        <NavLink to="/live" className={({ isActive }) => (isActive ? 'nav-active' : '')}>
          Live feed
        </NavLink>
        <NavLink to="/bans" className={({ isActive }) => (isActive ? 'nav-active' : '')}>
          Bans
        </NavLink>
        <NavLink to="/rules" className={({ isActive }) => (isActive ? 'nav-active' : '')}>
          Rules
        </NavLink>
        <NavLink to="/sources" className={({ isActive }) => (isActive ? 'nav-active' : '')}>
          Sources
        </NavLink>
        <NavLink to="/reports" className={({ isActive }) => (isActive ? 'nav-active' : '')}>
          Reports
        </NavLink>
      </nav>
      <span className="topbar-user">
        {user.email} ({user.role})
      </span>
      <button className="btn-ghost" type="button" onClick={logout}>
        Sign out
      </button>
    </header>
  );
}
