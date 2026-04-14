import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import api from '../api'

export default function Register() {
  const [form, setForm] = useState({ username: '', email: '', password: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await api.post('/auth/register', form)
      // 가입 성공 → 자동 로그인 후 대시보드 이동
      const params = new URLSearchParams()
      params.append('username', form.username)
      params.append('password', form.password)
      const { data } = await api.post('/auth/login', params)
      localStorage.setItem('token', data.access_token)
      navigate('/')
    } catch (err) {
      setError(err.response?.data?.detail || '회원가입 실패')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="auth-container">
      <h1>🍯 Honeypot Dashboard</h1>
      <form onSubmit={handleSubmit} className="auth-form">
        <h2>회원가입</h2>
        {error && <p className="error">{error}</p>}
        <input
          placeholder="사용자명"
          value={form.username}
          onChange={(e) => setForm({ ...form, username: e.target.value })}
          required
        />
        <input
          type="email"
          placeholder="이메일"
          value={form.email}
          onChange={(e) => setForm({ ...form, email: e.target.value })}
          required
        />
        <input
          type="password"
          placeholder="비밀번호"
          value={form.password}
          onChange={(e) => setForm({ ...form, password: e.target.value })}
          required
        />
        <button type="submit" disabled={loading}>
          {loading ? '허니팟 활성화 중...' : '회원가입'}
        </button>
        <p>이미 계정이 있으신가요? <Link to="/login">로그인</Link></p>
      </form>
    </div>
  )
}
