import { useEffect, useState } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import { getUsername, saveSession } from './lib/api'
import { AgentProvider } from './lib/agent'
import AccountPage from './pages/AccountPage'
import CardDetailPage from './pages/CardDetailPage'
import CardsPage from './pages/CardsPage'
import DashboardPage from './pages/DashboardPage'
import IssuePage from './pages/IssuePage'
import LoginPage from './pages/LoginPage'
import LogsPage from './pages/LogsPage'

export default function App() {
  const [user, setUser] = useState<string | null>(getUsername())

  // Server trả 401 (token hết hạn) -> quay về trang đăng nhập
  useEffect(() => {
    const onLogout = () => setUser(null)
    window.addEventListener('vault:logout', onLogout)
    return () => window.removeEventListener('vault:logout', onLogout)
  }, [])

  if (!user) {
    return (
      <Routes>
        <Route path="*" element={<LoginPage onLogin={setUser} />} />
      </Routes>
    )
  }

  const logout = () => {
    saveSession(null)
    setUser(null)
  }

  return (
    <AgentProvider>
      <Routes>
        <Route element={<Layout user={user} onLogout={logout} />}>
          <Route index element={<DashboardPage />} />
          <Route path="cards" element={<CardsPage />} />
          <Route path="cards/:id" element={<CardDetailPage />} />
          <Route path="issue" element={<IssuePage />} />
          <Route path="logs" element={<LogsPage />} />
          <Route path="account" element={<AccountPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </AgentProvider>
  )
}
