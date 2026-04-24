// Chart rendering

Chart.defaults.color = '#64748b';
Chart.defaults.borderColor = '#1e2d4a';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 11;

let timelineChart, typesChart;

function renderCharts(data) {
  renderTimelineChart(data.by_day || []);
  renderTypesChart(data.by_type || []);
}

function renderTimelineChart(byDay) {
  const ctx = document.getElementById('chart-timeline')?.getContext('2d');
  if (!ctx) return;

  const labels = byDay.map(d => {
    const date = new Date(d.day);
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  });
  const values = byDay.map(d => d.cnt);

  if (timelineChart) timelineChart.destroy();

  timelineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Threats',
        data: values,
        borderColor: '#3b82f6',
        backgroundColor: 'rgba(59,130,246,0.08)',
        borderWidth: 2,
        pointBackgroundColor: '#3b82f6',
        pointRadius: 3,
        fill: true,
        tension: 0.3,
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: '#1e2d4a' }, ticks: { color: '#64748b' } },
        y: { grid: { color: '#1e2d4a' }, ticks: { color: '#64748b', precision: 0 }, beginAtZero: true },
      },
    },
  });
}

function renderTypesChart(byType) {
  const ctx = document.getElementById('chart-types')?.getContext('2d');
  if (!ctx) return;

  const COLORS = [
    '#ef4444','#f97316','#eab308','#22c55e','#3b82f6',
    '#6366f1','#8b5cf6','#06b6d4','#10b981','#f43f5e',
  ];

  if (typesChart) typesChart.destroy();

  typesChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: byType.map(t => threatTypeLabel(t.threat_type)),
      datasets: [{
        data: byType.map(t => t.cnt),
        backgroundColor: COLORS.slice(0, byType.length).map(c => c + '99'),
        borderColor: COLORS.slice(0, byType.length),
        borderWidth: 1,
      }],
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          position: 'right',
          labels: { color: '#94a3b8', padding: 12, font: { size: 11 } },
        },
      },
      cutout: '65%',
    },
  });
}
