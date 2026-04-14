import { useState, useEffect, useRef, useCallback } from 'react'

export default function LogViewer({ containerName, onClose }) {
  const [lines, setLines] = useState([])
  const [connected, setConnected] = useState(false)
  const [autoScroll, setAutoScroll] = useState(true)
  const wsRef = useRef(null)
  const bottomRef = useRef(null)

  const connect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close()
    }

    const token = localStorage.getItem('token')
    const ws = new WebSocket(`ws://localhost:8000/ws/logs/${containerName}?token=${token}`)
    wsRef.current = ws

    ws.onopen = () => setConnected(true)

    ws.onmessage = (e) => {
      const incoming = e.data.split('\n').filter(l => l.trim())
      setLines(prev => {
        const next = [...prev, ...incoming]
        return next.length > 500 ? next.slice(-500) : next
      })
    }

    ws.onclose = () => setConnected(false)
    ws.onerror = () => setConnected(false)
  }, [containerName])

  useEffect(() => {
    connect()
    return () => wsRef.current?.close()
  }, [connect])

  useEffect(() => {
    if (autoScroll) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [lines, autoScroll])

  const handleClear = () => setLines([])

  return (
    <div className="logviewer-overlay">
      <div className="logviewer-panel">
        <div className="logviewer-header">
          <div className="logviewer-title">
            <span className={`ws-dot ${connected ? 'ws-connected' : 'ws-disconnected'}`} />
            <span>{containerName}</span>
            <span className="ws-status">{connected ? 'LIVE' : '연결 끊김'}</span>
          </div>
          <div className="logviewer-actions">
            <label className="autoscroll-toggle">
              <input
                type="checkbox"
                checked={autoScroll}
                onChange={e => setAutoScroll(e.target.checked)}
              />
              자동 스크롤
            </label>
            <button onClick={connect} className="btn-action btn-yellow">재연결</button>
            <button onClick={handleClear} className="btn-action btn-gray">지우기</button>
            <button onClick={onClose} className="btn-action btn-red-xs">닫기</button>
          </div>
        </div>
        <div className="logviewer-body">
          {lines.length === 0 && (
            <div className="logviewer-empty">로그를 기다리는 중...</div>
          )}
          {lines.map((line, i) => (
            <div key={i} className="log-line">{line}</div>
          ))}
          <div ref={bottomRef} />
        </div>
      </div>
    </div>
  )
}
