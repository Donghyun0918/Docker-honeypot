import { useState, useEffect, useRef, useCallback } from 'react'
import LogViewer from './LogViewer'

const HONEYPOTS = ['cowrie', 'heralding', 'opencanary', 'tanner', 'snare', 'dionaea', 'mailoney', 'conpot']

const HONEYPOT_COLOR = {
  cowrie:    '#60a5fa',
  heralding: '#a78bfa',
  opencanary:'#34d399',
  tanner:    '#94a3b8',
  snare:     '#f472b6',
  dionaea:   '#fb923c',
  mailoney:  '#facc15',
  conpot:    '#2dd4bf',
}

export default function ScenarioMonitor({ username, scenario, onClose }) {
  const [activity, setActivity] = useState({})   // { containerName: { count, lastAt } }
  const [selected, setSelected] = useState(null)
  const wsRefs = useRef({})
  const token = localStorage.getItem('token')

  const connectAll = useCallback(() => {
    HONEYPOTS.forEach(hp => {
      const name = `hp_${username}_${hp}`
      if (wsRefs.current[name]) wsRefs.current[name].close()

      const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const wsHost  = window.location.host
      const ws = new WebSocket(`${wsProto}//${wsHost}/ws/logs/${name}?token=${token}`)

      ws.onmessage = () => {
        setActivity(prev => ({
          ...prev,
          [hp]: { count: (prev[hp]?.count || 0) + 1, lastAt: Date.now() },
        }))
      }

      ws.onerror = () => {}
      wsRefs.current[name] = ws
    })
  }, [username, token])

  useEffect(() => {
    connectAll()
    return () => {
      Object.values(wsRefs.current).forEach(ws => ws.close())
    }
  }, [connectAll])

  const isActive = (hp) => {
    const a = activity[hp]
    return a && (Date.now() - a.lastAt) < 3000
  }

  return (
    <div className="monitor-overlay">
      <div className="monitor-panel">
        <div className="monitor-header">
          <div className="monitor-title">
            <span className="monitor-scenario-badge">{scenario.id}</span>
            <span>{scenario.name}</span>
            <span className={`scenario-state-dot ${scenario.state}`} />
            <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>{scenario.state === 'running' ? '실행 중' : scenario.state === 'done' ? '완료' : scenario.state}</span>
          </div>
          <button onClick={onClose} className="btn-action btn-red-xs">닫기</button>
        </div>

        <div className="monitor-grid">
          {HONEYPOTS.map(hp => {
            const active = isActive(hp)
            const a = activity[hp]
            const color = HONEYPOT_COLOR[hp]
            return (
              <div
                key={hp}
                className={`monitor-card ${active ? 'monitor-active' : ''}`}
                style={{ '--hp-color': color, borderColor: active ? color : undefined }}
                onClick={() => setSelected(`hp_${username}_${hp}`)}
              >
                <div className="monitor-hp-name">{hp}</div>
                <div className="monitor-indicator" style={{ background: active ? color : '#2d3148' }}>
                  {active && <span className="monitor-pulse" style={{ background: color }} />}
                </div>
                <div className="monitor-count" style={{ color: a?.count ? color : '#4b5563' }}>
                  {a?.count ? `${a.count} 이벤트` : '대기 중'}
                </div>
              </div>
            )
          })}
        </div>

        <p className="monitor-hint">카드 클릭 시 실시간 로그 열림</p>
      </div>

      {selected && (
        <LogViewer containerName={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  )
}
