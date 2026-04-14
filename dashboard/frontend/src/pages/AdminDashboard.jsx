import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api'
import LogViewer from '../components/LogViewer'

const STATE_COLOR = { done: '#22c55e', failed: '#ef4444', running: '#f59e0b' }
const LABEL_COLOR = {
  Recon: '#60a5fa', 'Brute Force': '#a78bfa', Intrusion: '#fb923c',
  Malware: '#f472b6', Etc: '#94a3b8',
}

const STATUS_COLOR = {
  running: '#22c55e',
  exited: '#ef4444',
  paused: '#f59e0b',
  not_found: '#6b7280',
  error: '#dc2626',
}

const SCENARIO_STATE_COLOR = {
  idle:    '#6b7280',
  running: '#f59e0b',
  done:    '#22c55e',
  failed:  '#ef4444',
}

const SCENARIO_STATE_LABEL = {
  idle:    '대기',
  running: '실행 중',
  done:    '완료',
  failed:  '실패',
}

export default function AdminDashboard() {
  const [me, setMe] = useState(null)
  const [users, setUsers] = useState([])
  const [containersByUser, setContainersByUser] = useState({})
  const [logs, setLogs] = useState({ name: '', content: '' })
  const [liveLog, setLiveLog] = useState('')
  const [scenarios, setScenarios] = useState([])
  const [scenarioOutput, setScenarioOutput] = useState({ id: '', content: '' })
  const [adminStats, setAdminStats] = useState([])
  const [history, setHistory] = useState([])
  const navigate = useNavigate()

  const fetchScenarios = useCallback(async () => {
    const res = await api.get('/admin/scenarios')
    setScenarios(res.data)
  }, [])

  const fetchAll = useCallback(async () => {
    const [meRes, usersRes, containersRes] = await Promise.all([
      api.get('/users/me'),
      api.get('/users'),
      api.get('/admin/containers'),
    ])
    setMe(meRes.data)
    setUsers(usersRes.data)
    setContainersByUser(containersRes.data)
  }, [])

  const fetchAdminStats = useCallback(async () => {
    try {
      const res = await api.get('/admin/stats')
      setAdminStats(res.data)
    } catch (_) {}
  }, [])

  const fetchHistory = useCallback(async () => {
    try {
      const res = await api.get('/admin/history')
      setHistory(res.data)
    } catch (_) {}
  }, [])

  useEffect(() => {
    fetchAll()
    fetchScenarios()
    fetchAdminStats()
    fetchHistory()
    const timer = setInterval(() => {
      fetchAll()
      fetchScenarios()
      fetchAdminStats()
    }, 5000)
    return () => clearInterval(timer)
  }, [fetchAll, fetchScenarios, fetchAdminStats, fetchHistory])

  const logout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('is_admin')
    navigate('/login')
  }

  const handleDeactivate = async (userId, username) => {
    if (!window.confirm(`${username} 유저를 비활성화하면 해당 유저의 허니팟 컨테이너가 삭제됩니다. 계속할까요?`)) return
    try {
      await api.delete(`/users/${userId}`)
      await fetchAll()
    } catch (err) {
      alert(err.response?.data?.detail || '비활성화 실패')
    }
  }

  const handleActivate = async (userId) => {
    try {
      await api.post(`/users/${userId}/activate`)
      await fetchAll()
    } catch (err) {
      alert(err.response?.data?.detail || '활성화 실패')
    }
  }

  const fetchLogs = (containerName) => {
    setLiveLog(containerName)
  }

  const handleRunScenario = async (scenarioId) => {
    try {
      await api.post(`/scenarios/${scenarioId}/run`)
      await fetchScenarios()
    } catch (err) {
      alert(err.response?.data?.detail || '시나리오 실행 실패')
    }
  }

  const fetchScenarioOutput = async (scenarioId) => {
    const res = await api.get(`/scenarios/${scenarioId}`)
    setScenarioOutput({ id: scenarioId, content: res.data.output || '(출력 없음)' })
  }

  const handleContainerAction = async (containerName, action) => {
    try {
      await api.post(`/containers/${containerName}/${action}`)
      await fetchAll()
    } catch (err) {
      alert(err.response?.data?.detail || `${action} 실패`)
    }
  }

  const activeUsers = users.filter(u => u.is_active && !u.is_admin)
  const inactiveUsers = users.filter(u => !u.is_active)
  const totalContainers = Object.values(containersByUser).flat()
  const runningCount = totalContainers.filter(c => c.status === 'running').length

  return (
    <div className="dashboard">
      <header className="dash-header">
        <div className="header-left">
          <h1>🍯 Honeypot Dashboard</h1>
          <span className="admin-badge">관리자</span>
        </div>
        <div className="header-right">
          {me && <span>{me.username}</span>}
          <button onClick={fetchAll} className="btn-outline">새로고침</button>
          <button onClick={logout} className="btn-outline">로그아웃</button>
        </div>
      </header>

      <main className="dash-main">
        {/* 요약 */}
        <div className="summary-grid">
          <div className="summary-card">
            <div className="summary-label">활성 유저</div>
            <div className="summary-value" style={{ color: '#22c55e' }}>{activeUsers.length}</div>
          </div>
          <div className="summary-card">
            <div className="summary-label">비활성 유저</div>
            <div className="summary-value" style={{ color: '#ef4444' }}>{inactiveUsers.length}</div>
          </div>
          <div className="summary-card">
            <div className="summary-label">전체 유저</div>
            <div className="summary-value">{users.length}</div>
          </div>
          <div className="summary-card">
            <div className="summary-label">실행 중 컨테이너</div>
            <div className="summary-value" style={{ color: runningCount > 0 ? '#22c55e' : '#6b7280' }}>
              {runningCount} / {totalContainers.length}
            </div>
          </div>
        </div>

        {/* 유저별 컨테이너 */}
        {activeUsers.length > 0 && (
          <section className="card">
            <h2>유저별 허니팟 컨테이너</h2>
            <div className="user-containers-list">
              {activeUsers.map(u => {
                const containers = containersByUser[u.username] || []
                const running = containers.filter(c => c.status === 'running').length
                return (
                  <div key={u.id} className="user-container-group">
                    <div className="ucg-header">
                      <span className="ucg-username">{u.username}</span>
                      <span className="ucg-count" style={{ color: running === containers.length ? '#22c55e' : '#f59e0b' }}>
                        {running}/{containers.length} 실행 중
                      </span>
                    </div>
                    <div className="container-grid-sm">
                      {containers.map(c => (
                        <div key={c.name} className="container-card-sm">
                          <div className="container-name">{c.honeypot}</div>
                          <div className="container-status" style={{ color: STATUS_COLOR[c.status] || '#fff' }}>
                            ● {c.status}
                          </div>
                          {c.id && <div className="container-id">{c.id}</div>}
                          <div className="container-actions">
                            {c.status === 'running' ? (
                              <>
                                <button onClick={() => handleContainerAction(c.name, 'restart')} className="btn-action btn-yellow">재시작</button>
                                <button onClick={() => handleContainerAction(c.name, 'stop')} className="btn-action btn-red-xs">정지</button>
                              </>
                            ) : (
                              <button onClick={() => handleContainerAction(c.name, 'start')} className="btn-action btn-green-xs">시작</button>
                            )}
                            <button onClick={() => fetchLogs(c.name)} className="btn-action btn-gray">로그</button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )
              })}
            </div>
          </section>
        )}

        {/* 공격 시나리오 현황 (유저별) */}
        {Object.keys(scenarios).length > 0 && (
          <section className="card">
            <h2>공격 시나리오 현황</h2>
            {Object.entries(scenarios).map(([username, userScenarios]) => (
              <div key={username} className="user-container-group" style={{ marginTop: 16 }}>
                <div className="ucg-header">
                  <span className="ucg-username">{username}</span>
                  <span className="ucg-count" style={{ color: '#94a3b8' }}>
                    완료: {userScenarios.filter(s => s.state === 'done').length} /
                    실패: {userScenarios.filter(s => s.state === 'failed').length} /
                    실행 중: {userScenarios.filter(s => s.state === 'running').length}
                  </span>
                </div>
                <div className="scenario-grid">
                  {userScenarios.map(s => (
                    <div key={s.id} className="scenario-card">
                      <div className="scenario-header">
                        <span className="scenario-id">{s.id}</span>
                        <span className="scenario-name">{s.name}</span>
                        <span className="scenario-label">{s.label}</span>
                      </div>
                      <div className="scenario-state" style={{ color: SCENARIO_STATE_COLOR[s.state] }}>
                        ● {SCENARIO_STATE_LABEL[s.state]}
                      </div>
                      {s.started_at && (
                        <div className="scenario-time">
                          {new Date(s.started_at + 'Z').toLocaleTimeString('ko-KR')}
                          {s.finished_at && ` → ${new Date(s.finished_at + 'Z').toLocaleTimeString('ko-KR')}`}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </section>
        )}

        {/* 시나리오 출력 뷰어 */}
        {scenarioOutput.content && (
          <section className="card">
            <div className="card-header">
              <h2>시나리오 출력: {scenarioOutput.id}</h2>
              <button onClick={() => setScenarioOutput({ id: '', content: '' })} className="btn-outline">닫기</button>
            </div>
            <pre className="log-viewer">{scenarioOutput.content}</pre>
          </section>
        )}

        {/* 실시간 로그 뷰어 */}
        {liveLog && (
          <LogViewer containerName={liveLog} onClose={() => setLiveLog('')} />
        )}

        {/* 유저별 데이터셋 & 시나리오 통계 */}
        {adminStats.length > 0 && (
          <section className="card">
            <div className="card-header">
              <h2>유저별 현황</h2>
              <button onClick={fetchAdminStats} className="btn-outline">새로고침</button>
            </div>
            <div className="history-table-wrap">
              <table className="history-table">
                <thead>
                  <tr>
                    <th>유저</th>
                    <th>데이터셋 행 수</th>
                    <th>CSV 크기</th>
                    <th>생성 시각</th>
                    <th>시나리오 완료</th>
                    <th>시나리오 실패</th>
                    <th>총 실행</th>
                  </tr>
                </thead>
                <tbody>
                  {adminStats.map(u => (
                    <tr key={u.username}>
                      <td style={{ fontWeight: 600 }}>{u.username}</td>
                      <td style={{ color: u.dataset ? '#60a5fa' : '#4b5563' }}>
                        {u.dataset ? u.dataset.row_count.toLocaleString() : '-'}
                      </td>
                      <td style={{ color: '#94a3b8', fontSize: '0.8rem' }}>
                        {u.dataset ? `${(u.dataset.size / 1024).toFixed(1)} KB` : '-'}
                      </td>
                      <td style={{ color: '#94a3b8', fontSize: '0.8rem' }}>
                        {u.dataset?.generated_at
                          ? new Date(u.dataset.generated_at).toLocaleString('ko-KR')
                          : '-'}
                      </td>
                      <td style={{ color: '#22c55e' }}>{u.runs_done}</td>
                      <td style={{ color: u.runs_failed > 0 ? '#ef4444' : '#4b5563' }}>{u.runs_failed}</td>
                      <td style={{ color: '#94a3b8' }}>{u.runs_total}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* 전체 시나리오 실행 이력 */}
        {history.length > 0 && (
          <section className="card">
            <div className="card-header">
              <h2>시나리오 실행 이력 (전체)</h2>
              <button onClick={fetchHistory} className="btn-outline">새로고침</button>
            </div>
            <div className="history-table-wrap">
              <table className="history-table">
                <thead>
                  <tr>
                    <th>유저</th>
                    <th>#</th>
                    <th>시나리오</th>
                    <th>분류</th>
                    <th>결과</th>
                    <th>완료 시각</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map(r => (
                    <tr key={r.id}>
                      <td style={{ fontWeight: 600 }}>{r.username}</td>
                      <td style={{ color: '#4b5563' }}>{r.scenario_id}</td>
                      <td>{r.scenario_name}</td>
                      <td>
                        <span className="history-label" style={{ background: (LABEL_COLOR[r.label] || '#94a3b8') + '22', color: LABEL_COLOR[r.label] || '#94a3b8' }}>
                          {r.label}
                        </span>
                      </td>
                      <td><span style={{ color: STATE_COLOR[r.state] }}>● {r.state}</span></td>
                      <td style={{ color: '#94a3b8', fontSize: '0.8rem' }}>
                        {r.finished_at ? new Date(r.finished_at + 'Z').toLocaleString('ko-KR') : '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* 유저 관리 테이블 */}
        <section className="card">
          <h2>유저 관리</h2>
          <table className="user-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>사용자명</th>
                <th>이메일</th>
                <th>권한</th>
                <th>상태</th>
                <th>가입일</th>
                <th>비활성화일</th>
                <th>액션</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} style={{ opacity: u.is_active ? 1 : 0.5 }}>
                  <td>{u.id}</td>
                  <td>{u.username}</td>
                  <td>{u.email}</td>
                  <td>
                    {u.is_admin
                      ? <span className="badge-admin">관리자</span>
                      : <span className="badge-user">일반</span>}
                  </td>
                  <td>
                    <span style={{ color: u.is_active ? '#22c55e' : '#ef4444' }}>
                      {u.is_active ? '활성' : '비활성'}
                    </span>
                  </td>
                  <td>{new Date(u.created_at).toLocaleString('ko-KR')}</td>
                  <td>{u.deactivated_at ? new Date(u.deactivated_at).toLocaleString('ko-KR') : '-'}</td>
                  <td>
                    {!u.is_admin && (
                      u.is_active
                        ? <button onClick={() => handleDeactivate(u.id, u.username)} className="btn-red-sm">비활성화</button>
                        : <button onClick={() => handleActivate(u.id)} className="btn-green-sm">활성화</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </main>
    </div>
  )
}
