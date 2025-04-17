  const themeToggleBtn = document.getElementById('themeToggle');
  const root = document.documentElement;

  themeToggleBtn.addEventListener('click', () => {
    if (root.style.getPropertyValue('--dark-bg') === '#ffffff') {
      root.style.setProperty('--dark-bg', '#0c121f');
      root.style.setProperty('--card-bg', '#1a2332');
      root.style.setProperty('--text-color', '#ffffff');
    } else {
      root.style.setProperty('--dark-bg', '#ffffff');
      root.style.setProperty('--card-bg', '#f4f4f4');
      root.style.setProperty('--text-color', '#000000');
    }
  });

  document.addEventListener('DOMContentLoaded', () => {
    const userCtx = document.getElementById('userChart').getContext('2d');
    new Chart(userCtx, {
      type: 'line',
      data: {
        labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
        datasets: [{
          label: 'User Growth',
          data: [1000, 2000, 3000, 4500, 6000, 8000],
          borderColor: '#00e5ff',
          backgroundColor: 'rgba(0, 229, 255, 0.1)',
          fill: true,
          tension: 0.4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            labels: { color: 'rgba(255, 255, 255, 0.8)' }
          }
        },
        scales: {
          y: {
            grid: { color: 'rgba(255, 255, 255, 0.1)' },
            ticks: { color: 'rgba(255, 255, 255, 0.8)' }
          },
          x: {
            grid: { color: 'rgba(255, 255, 255, 0.1)' },
            ticks: { color: 'rgba(255, 255, 255, 0.8)' }
          }
        }
      }
    });

    const responseCtx = document.getElementById('responseChart').getContext('2d');
    new Chart(responseCtx, {
      type: 'doughnut',
      data: {
        labels: ['< 1 hour', '1-3 hours', '3-6 hours', '> 6 hours'],
        datasets: [{
          data: [60, 25, 10, 5],
          backgroundColor: ['#00e5ff', '#b24bff', '#ff2e88', 'rgba(255, 255, 255, 0.2)']
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: 'rgba(255, 255, 255, 0.8)' }
          }
        }
      }
    });
  });
