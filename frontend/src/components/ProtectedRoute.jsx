import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../auth';

export default function ProtectedRoute() {
  const { user, loading } = useAuth();
  if (loading) {
    return <p className="page-status">Checking session…</p>;
  }
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return <Outlet />;
}
