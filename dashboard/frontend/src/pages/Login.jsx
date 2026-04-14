import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import api from '../api'

export default function Login() {
  const [form, setForm] = useState({ username: '', password: '' })
  const [error, setError] = useState('')
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    try {
      const params = new URLSearchParams()
      params.append('username', form.username)
      params.append('password', form.password)
      const { data } = await api.post('/auth/login', params)
      localStorage.setItem('token', data.access_token)
      localStorage.setItem('is_admin', data.is_admin ? 'true' : 'false')
      navigate(data.is_admin ? '/admin' : '/')
    } catch (err) {
      setError(err.response?.data?.detail || '로그인 실패')
    }
  }

  return (
    <div className="auth-container">
      <h1>🍯 Honeypot Dashboard</h1>
      <form onSubmit={handleSubmit} className="auth-form">
        <h2>로그인</h2>
        {error && <p className="error">{error}</p>}
        <input
          placeholder="사용자명"
          value={form.username}
          onChange={(e) => setForm({ ...form, username: e.target.value })}
          required
        />
        <input
          type="password"
          placeholder="비밀번호"
          value={form.password}
          onChange={(e) => setForm({ ...form, password: e.target.value })}
          required
        />
        <button type="submit">로그인</button>
        <p>계정이 없으신가요? <Link to="/register">회원가입</Link></p>
      </form>
    </div>
  )
}
