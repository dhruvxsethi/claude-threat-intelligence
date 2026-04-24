Chart.defaults.color = '#5a6a8a';
Chart.defaults.borderColor = '#1a2540';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 11;

let _tl, _ty;

function renderCharts(d) {
  renderTimeline(d.by_day||[]);
  renderTypes(d.by_type||[]);
}

function renderTimeline(data) {
  const ctx = document.getElementById('chart-timeline')?.getContext('2d');
  if (!ctx) return;
  if (_tl) _tl.destroy();
  _tl = new Chart(ctx, {
    type: 'line',
    data: {
      labels: data.map(d => new Date(d.day).toLocaleDateString('en-US',{month:'short',day:'numeric'})),
      datasets: [{
        data: data.map(d=>d.cnt),
        borderColor: '#3d7aff',
        backgroundColor: 'rgba(61,122,255,.06)',
        borderWidth: 2,
        pointBackgroundColor: '#3d7aff',
        pointRadius: 3,
        fill: true,
        tension: 0.4,
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: '#1a2540' }, ticks: { color: '#5a6a8a' } },
        y: { grid: { color: '#1a2540' }, ticks: { color: '#5a6a8a', precision: 0 }, beginAtZero: true },
      },
    },
  });
}

function renderTypes(data) {
  const ctx = document.getElementById('chart-types')?.getContext('2d');
  if (!ctx) return;
  if (_ty) _ty.destroy();
  const COLORS = ['#ff4560','#ff8c42','#ffd166','#06d6a0','#3d7aff','#9b59ff','#06b6d4','#f59e0b','#84cc16','#f43f5e'];
  _ty = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: data.map(d=>typeLabel(d.threat_type)),
      datasets: [{
        data: data.map(d=>d.cnt),
        backgroundColor: COLORS.slice(0,data.length).map(c=>c+'33'),
        borderColor: COLORS.slice(0,data.length),
        borderWidth: 1.5,
      }],
    },
    options: {
      responsive: true,
      plugins: {
        legend: { position:'right', labels: { color:'#a8b4d0', padding:10, font:{size:11} } },
      },
      cutout: '68%',
    },
  });
}
