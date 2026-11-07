import { BrowserRouter, Route, Routes } from 'react-router-dom';
import { AuthProvider } from './auth.jsx';
import ProtectedRoute from './components/ProtectedRoute.jsx';
import Login from './pages/Login.jsx';
import Dashboard from './pages/Dashboard.jsx';
import LiveFeed from './pages/LiveFeed.jsx';
import Bans from './pages/Bans.jsx';
import IpDetail from './pages/IpDetail.jsx';
import Rules from './pages/Rules.jsx';
import Sources from './pages/Sources.jsx';
import Reports from './pages/Reports.jsx';

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route element={<ProtectedRoute />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/live" element={<LiveFeed />} />
            <Route path="/bans" element={<Bans />} />
            <Route path="/ips/:ip" element={<IpDetail />} />
            <Route path="/rules" element={<Rules />} />
            <Route path="/sources" element={<Sources />} />
            <Route path="/reports" element={<Reports />} />
          </Route>
          <Route path="*" element={<Login />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
