import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api'
import LogViewer from '../components/LogViewer'
import ScenarioMonitor from '../components/ScenarioMonitor'
import StatsCharts from '../components/StatsCharts'

const DATASET_INITIAL = { dataset_csv: null, dataset_meta: null, generating: false, error: '' }
const STATS_INITIAL   = { data: null, loading: false, error: '' }

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

export default function Dashboard() {
  const [me, setMe] = useState(null)
  const [containers, setContainers] = useState([])
  const [scenarios, setScenarios] = useState([])
  const [scenarioOutput, setScenarioOutput] = useState({ id: '', content: '' })
  const [liveLog, setLiveLog] = useState('')
  const [monitorScenario, setMonitorScenario] = useState(null)
  const [dataset, setDataset] = useState(DATASET_INITIAL)
  const [stats, setStats] = useState(STATS_INITIAL)
  const [history, setHistory] = useState([])
  const navigate = useNavigate()

  const fetchScenarios = useCallback(async () => {
    const res = await api.get('/scenarios')
    setScenarios(res.data)
  }, [])

  const fetchAll = useCallback(async () => {
    const [meRes, containersRes] = await Promise.all([
      api.get('/users/me'),
      api.get('/containers'),
    ])
    setMe(meRes.data)
    setContainers(containersRes.data)
  }, [])

  const fetchDatasetStatus = useCallback(async () => {
    try {
      const res = await api.get('/dataset/status')
      const d = res.data
      setDataset(prev => ({
        ...prev,
        dataset_csv: d['dataset.csv'],
        dataset_meta: d['dataset_meta.json'],
      }))
      return d
    } catch (_) { return null }
  }, [])

  const fetchHistory = useCallback(async () => {
    try {
      const res = await api.get('/history')
      setHistory(res.data)
    } catch (_) {}
  }, [])

  const fetchStats = useCallback(async () => {
    setStats(prev => ({ ...prev, loading: true, error: '' }))
    try {
      const res = await api.get('/stats')
      setStats({ data: res.data, loading: false, error: '' })
    } catch (err) {
      // 데이터셋 없으면 조용히 무시
      setStats({ data: null, loading: false, error: '' })
    }
  }, [])

  useEffect(() => {
    fetchAll()
    fetchScenarios()
    fetchDatasetStatus()
    fetchStats()
    fetchHistory()
    const timer = setInterval(async () => {
      fetchAll()
      const res = await api.get('/scenarios')
      setScenarios(res.data)
      // 모니터 중인 시나리오 상태 동기화
      if (monitorScenario) {
        const updated = res.data.find(s => s.id === monitorScenario.id)
        if (updated) setMonitorScenario(updated)
      }
    }, 5000)
    return () => clearInterval(timer)
  }, [fetchAll, fetchScenarios, fetchDatasetStatus, fetchStats, fetchHistory, monitorScenario])

  const logout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('is_admin')
    navigate('/login')
  }

  const handleRunScenario = async (scenarioId) => {
    try {
      await api.post(`/scenarios/${scenarioId}/run`)
      await fetchScenarios()
      const res = await api.get(`/scenarios/${scenarioId}`)
      setMonitorScenario(res.data)
    } catch (err) {
      alert(err.response?.data?.detail || '시나리오 실행 실패')
    }
  }

  // 시나리오 완료 감지 → 히스토리 갱신
  useEffect(() => {
    const hasDone = scenarios.some(s => s.state === 'done' || s.state === 'failed')
    if (hasDone) fetchHistory()
  }, [scenarios, fetchHistory])

  const handleGenerateDataset = async () => {
    setDataset(prev => ({ ...prev, generating: true, error: '' }))
    try {
      await api.post('/dataset/generate')
      await fetchDatasetStatus()
      await fetchStats()
    } catch (err) {
      setDataset(prev => ({ ...prev, error: err.response?.data?.detail || '생성 실패' }))
    } finally {
      setDataset(prev => ({ ...prev, generating: false }))
    }
  }

  const handleDownloadDataset = async (filename) => {
    try {
      const res = await api.get('/dataset/download', {
        params: { filename },
        responseType: 'blob',
      })
      const url = URL.createObjectURL(res.data)
      const a = document.createElement('a')
      a.href = url
      a.download = `${me?.username}_${filename}`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      alert('다운로드 실패: ' + (err.response?.data?.detail || err.message))
    }
  }

  const fetchScenarioOutput = async (scenarioId) => {
    const res = await api.get(`/scenarios/${scenarioId}`)
    setScenarioOutput({ id: scenarioId, content: res.data.output || '(출력 없음)' })
  }

  const runningCount = containers.filter(c => c.status === 'running').length

  return (
    <div className="dashboard">
      <header className="dash-header">
        <h1>🍯 Honeypot Dashboard</h1>
        <div className="header-right">
          {me && <span>{me.username}</span>}
          <button onClick={logout} className="btn-outline">로그아웃</button>
        </div>
      </header>

      <main className="dash-main">
        {/* 내 정보 */}
        {me && (
          <section className="card">
            <h2>내 계정</h2>
            <div className="info-grid">
              <div><span className="info-label">사용자명</span><span>{me.username}</span></div>
              <div><span className="info-label">이메일</span><span>{me.email}</span></div>
              <div><span className="info-label">상태</span>
                <span style={{ color: me.is_active ? '#22c55e' : '#ef4444' }}>
                  {me.is_active ? '활성' : '비활성'}
                </span>
              </div>
              <div><span className="info-label">가입일</span>
                <span>{new Date(me.created_at).toLocaleString('ko-KR')}</span>
              </div>
            </div>
          </section>
        )}

        {/* 컨테이너 상태 */}
        <section className="card">
          <div className="card-header">
            <h2>내 허니팟 컨테이너</h2>
            <div className="header-right">
              <span style={{ color: runningCount > 0 ? '#22c55e' : '#ef4444', fontSize: '0.875rem' }}>
                {runningCount} / {containers.length} 실행 중
              </span>
              <button onClick={fetchAll} className="btn-outline">새로고침</button>
            </div>
          </div>
          <div className="container-grid">
            {containers.map((c) => (
              <div key={c.name} className="container-card" style={{ cursor: c.status === 'running' ? 'pointer' : 'default' }}
                onClick={() => c.status === 'running' && setLiveLog(c.name)}>
                <div className="container-name">{c.honeypot || c.name}</div>
                <div className="container-status" style={{ color: STATUS_COLOR[c.status] || '#fff' }}>
                  ● {c.status}
                </div>
                {c.id && <div className="container-id">{c.id}</div>}
                {c.status === 'running' && <div className="container-hint">클릭하여 실시간 로그</div>}
              </div>
            ))}
          </div>
        </section>

        {/* 공격 시나리오 */}
        <section className="card">
          <div className="card-header">
            <h2>공격 시나리오</h2>
            <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>내 허니팟을 대상으로 실행됩니다</span>
          </div>
          <div className="scenario-grid">
            {scenarios.map(s => (
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
                    시작: {new Date(s.started_at + 'Z').toLocaleTimeString('ko-KR')}
                    {s.finished_at && ` / 종료: ${new Date(s.finished_at + 'Z').toLocaleTimeString('ko-KR')}`}
                  </div>
                )}
                <div className="scenario-actions">
                  <button
                    onClick={() => handleRunScenario(s.id)}
                    disabled={s.state === 'running' || runningCount === 0}
                    className="btn-action btn-green-xs"
                    title={runningCount === 0 ? '허니팟이 실행 중이어야 합니다' : ''}
                  >
                    {s.state === 'running' ? '실행 중...' : '실행'}
                  </button>
                  {(s.state === 'done' || s.state === 'failed') && (
                    <button onClick={() => fetchScenarioOutput(s.id)} className="btn-action btn-gray">
                      출력
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* 데이터셋 */}
        <section className="card">
          <div className="card-header">
            <h2>데이터셋</h2>
            <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>허니팟 로그 → dataset.csv</span>
          </div>
          <div className="dataset-row">
            <button
              onClick={handleGenerateDataset}
              disabled={dataset.generating}
              className="btn-action btn-green-xs"
            >
              {dataset.generating ? '생성 중...' : '데이터셋 생성'}
            </button>
            {dataset.dataset_csv?.exists && (
              <button onClick={() => handleDownloadDataset('dataset.csv')} className="btn-action btn-gray">
                CSV 다운로드
              </button>
            )}
            {dataset.dataset_meta?.exists && (
              <button onClick={() => handleDownloadDataset('dataset_meta.json')} className="btn-action btn-gray">
                메타 JSON
              </button>
            )}
          </div>
          {dataset.error && <div className="dataset-error">{dataset.error}</div>}
          {dataset.dataset_csv?.exists && (
            <div className="dataset-info">
              <span>dataset.csv</span>
              <span>{(dataset.dataset_csv.size / 1024).toFixed(1)} KB</span>
              <span>{new Date(dataset.dataset_csv.mtime * 1000).toLocaleString('ko-KR')}</span>
            </div>
          )}
          {!dataset.dataset_csv?.exists && !dataset.generating && (
            <div className="dataset-empty">아직 생성된 데이터셋이 없습니다.</div>
          )}
        </section>

        {/* 통계 차트 */}
        {(stats.data || stats.loading) && (
          <section className="card">
            <div className="card-header">
              <h2>통계</h2>
              <button onClick={fetchStats} className="btn-outline" disabled={stats.loading}>
                {stats.loading ? '로딩 중...' : '새로고침'}
              </button>
            </div>
            {stats.loading
              ? <div style={{ color: '#94a3b8', fontSize: '0.875rem' }}>통계 로딩 중...</div>
              : <StatsCharts stats={stats.data} />
            }
          </section>
        )}

        {/* 시나리오 실행 이력 */}
        {history.length > 0 && (
          <section className="card">
            <div className="card-header">
              <h2>시나리오 실행 이력</h2>
              <button onClick={fetchHistory} className="btn-outline">새로고침</button>
            </div>
            <div className="history-table-wrap">
              <table className="history-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>시나리오</th>
                    <th>분류</th>
                    <th>결과</th>
                    <th>시작</th>
                    <th>종료</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map(r => (
                    <tr key={r.id}>
                      <td style={{ color: '#4b5563' }}>{r.scenario_id}</td>
                      <td>{r.scenario_name}</td>
                      <td>
                        <span className="history-label" style={{ background: LABEL_COLOR[r.label] + '22', color: LABEL_COLOR[r.label] }}>
                          {r.label}
                        </span>
                      </td>
                      <td>
                        <span style={{ color: STATE_COLOR[r.state] }}>● {r.state}</span>
                      </td>
                      <td style={{ color: '#94a3b8', fontSize: '0.8rem' }}>
                        {r.started_at ? new Date(r.started_at + 'Z').toLocaleString('ko-KR') : '-'}
                      </td>
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

        {/* 실시간 로그 뷰어 */}
        {liveLog && <LogViewer containerName={liveLog} onClose={() => setLiveLog('')} />}

        {/* 시나리오 모니터 */}
        {monitorScenario && me && (
          <ScenarioMonitor
            username={me.username}
            scenario={monitorScenario}
            onClose={() => setMonitorScenario(null)}
          />
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
      </main>
    </div>
  )
}
