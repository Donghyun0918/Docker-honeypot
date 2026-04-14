import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
  LineChart, Line, CartesianGrid,
} from 'recharts'

const COLORS = [
  '#60a5fa', '#a78bfa', '#34d399', '#fb923c',
  '#f472b6', '#facc15', '#2dd4bf', '#f87171',
  '#818cf8', '#86efac',
]

const RADIAN = Math.PI / 180
const renderCustomLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent }) => {
  if (percent < 0.05) return null
  const r = innerRadius + (outerRadius - innerRadius) * 0.55
  const x = cx + r * Math.cos(-midAngle * RADIAN)
  const y = cy + r * Math.sin(-midAngle * RADIAN)
  return (
    <text x={x} y={y} fill="#fff" textAnchor="middle" dominantBaseline="central" fontSize={11}>
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  )
}

function Section({ title, children }) {
  return (
    <div className="stat-section">
      <div className="stat-section-title">{title}</div>
      {children}
    </div>
  )
}

export default function StatsCharts({ stats }) {
  if (!stats) return null

  const { row_count, generated_at, distributions, timeline } = stats

  const honeypotData = Object.entries(distributions.source_honeypot || {})
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)

  const protocolData = Object.entries(distributions.protocol || {})
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)

  const eventTypeData = Object.entries(distributions.event_type || {})
    .map(([name, value]) => ({ name, value }))

  return (
    <div className="stats-wrapper">
      {/* 요약 */}
      <div className="stats-summary">
        <div className="stats-kv">
          <span className="stats-k">총 이벤트</span>
          <span className="stats-v" style={{ color: '#60a5fa' }}>{row_count.toLocaleString()}</span>
        </div>
        <div className="stats-kv">
          <span className="stats-k">생성 시각</span>
          <span className="stats-v">{generated_at ? new Date(generated_at).toLocaleString('ko-KR') : '-'}</span>
        </div>
      </div>

      <div className="stats-grid">
        {/* 허니팟별 이벤트 수 */}
        <Section title="허니팟별 이벤트">
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={honeypotData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
              <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: '#1e2130', border: '1px solid #2d3148', borderRadius: 8 }}
                labelStyle={{ color: '#e2e8f0' }}
                itemStyle={{ color: '#94a3b8' }}
              />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {honeypotData.map((_, i) => (
                  <Cell key={i} fill={COLORS[i % COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Section>

        {/* 이벤트 타입 파이 */}
        <Section title="이벤트 타입">
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={eventTypeData}
                cx="50%"
                cy="50%"
                outerRadius={75}
                dataKey="value"
                labelLine={false}
                label={renderCustomLabel}
              >
                {eventTypeData.map((_, i) => (
                  <Cell key={i} fill={COLORS[i % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#1e2130', border: '1px solid #2d3148', borderRadius: 8 }}
                itemStyle={{ color: '#94a3b8' }}
              />
              <Legend
                iconType="circle"
                iconSize={8}
                wrapperStyle={{ fontSize: 11, color: '#94a3b8' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </Section>

        {/* 프로토콜별 */}
        <Section title="프로토콜별 이벤트">
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={protocolData} layout="vertical" margin={{ top: 4, right: 20, left: 30, bottom: 0 }}>
              <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <YAxis type="category" dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} width={60} />
              <Tooltip
                contentStyle={{ background: '#1e2130', border: '1px solid #2d3148', borderRadius: 8 }}
                labelStyle={{ color: '#e2e8f0' }}
                itemStyle={{ color: '#94a3b8' }}
              />
              <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                {protocolData.map((_, i) => (
                  <Cell key={i} fill={COLORS[i % COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Section>

        {/* 시간대별 이벤트 */}
        {timeline.length > 0 && (
          <Section title="시간대별 이벤트">
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={timeline} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2d3148" />
                <XAxis
                  dataKey="hour"
                  tick={{ fill: '#94a3b8', fontSize: 10 }}
                  tickFormatter={v => v.slice(11)}
                />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ background: '#1e2130', border: '1px solid #2d3148', borderRadius: 8 }}
                  labelStyle={{ color: '#e2e8f0' }}
                  itemStyle={{ color: '#94a3b8' }}
                />
                <Line type="monotone" dataKey="count" stroke="#60a5fa" strokeWidth={2} dot={{ r: 3, fill: '#60a5fa' }} />
              </LineChart>
            </ResponsiveContainer>
          </Section>
        )}
      </div>
    </div>
  )
}
