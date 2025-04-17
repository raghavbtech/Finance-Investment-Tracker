
// Enhanced script for Finance Tracker with calculator and chart functionality
document.addEventListener('DOMContentLoaded', () => {
// Navbar functionality
const menuBtn = document.querySelector('.menu-btn');
const navLinks = document.querySelector('.nav-links');

menuBtn?.addEventListener('click', () => {
 navLinks.classList.toggle('active');
});

document.addEventListener('click', (e) => {
 if (!menuBtn.contains(e.target) && !navLinks.contains(e.target)) {
     navLinks.classList.remove('active');
 }
});

window.addEventListener('resize', () => {
 if (window.innerWidth > 768) {
     navLinks.classList.remove('active');
 }
});

// ==================== CALCULATOR FUNCTIONALITY ====================

// Quick Calculator
const quickCalcBtn = document.querySelector('.form-card:nth-child(1) .calc-button');
const amountInput = document.querySelector('.form-card:nth-child(1) .calc-input');
const calcTypeSelect = document.querySelector('.form-card:nth-child(1) .calc-select');

quickCalcBtn?.addEventListener('click', () => {
 const amount = parseFloat(amountInput.value);
 const calcType = calcTypeSelect.value;
 
 if (!amount || isNaN(amount)) {
     showResult('Please enter a valid amount', 'error', 1);
     return;
 }
 
 let result;
 switch(calcType) {
     case 'savings':
         // Calculate 1-year savings with 2.5% interest
         result = amount * (1 + 0.025);
         showResult(After 1 year, your savings will be: $${result.toFixed(2)}, 'success', 1);
         break;
     case 'investment':
         // Calculate 1-year investment with 7% return
         result = amount * (1 + 0.07);
         showResult(Estimated investment value after 1 year: $${result.toFixed(2)}, 'success', 1);
         break;
     case 'loan':
         // Calculate monthly payment for a 5-year loan at 5% interest
         const rate = 0.05 / 12;
         const term = 5 * 12;
         result = amount * (rate * Math.pow(1 + rate, term)) / (Math.pow(1 + rate, term) - 1);
         showResult(Monthly payment for a 5-year loan: $${result.toFixed(2)}, 'success', 1);
         break;
 }
});

// Savings Goal Calculator
const goalBtn = document.querySelector('.form-card:nth-child(2) .goal-button');
const goalAmountInput = document.querySelector('.form-card:nth-child(2) .goal-input');
const goalDateInput = document.querySelector('.form-card:nth-child(2) .goal-date');

goalBtn?.addEventListener('click', () => {
 const targetAmount = parseFloat(goalAmountInput.value);
 const targetDate = new Date(goalDateInput.value);
 const today = new Date();
 
 if (!targetAmount || isNaN(targetAmount)) {
     showResult('Please enter a valid target amount', 'error', 2);
     return;
 }
 
 if (!goalDateInput.value || targetDate <= today) {
     showResult('Please enter a future date', 'error', 2);
     return;
 }
 
 // Calculate months between dates
 const monthsDiff = (targetDate.getFullYear() - today.getFullYear()) * 12 + 
                    (targetDate.getMonth() - today.getMonth());
 
 // Calculate monthly savings needed
 const monthlySavings = targetAmount / monthsDiff;
 
 showResult(`To reach your goal of $${targetAmount.toFixed(2)} by ${formatDate(targetDate)}, 
            you need to save $${monthlySavings.toFixed(2)} monthly.`, 'success', 2);
});

// Quick Budget Calculator
const budgetInput = document.querySelector('.form-card:nth-child(3) .budget-input');
const savingsSlider = document.querySelector('.budget-sliders input:first-of-type');
const expensesSlider = document.querySelector('.budget-sliders input:last-of-type');
const savingsValue = document.querySelector('.savings-value');
const expensesValue = document.querySelector('.expenses-value');

// Update sliders to be synchronized (when one changes, the other adjusts to make total 100%)
savingsSlider?.addEventListener('input', (e) => {
 const savingsPercent = parseInt(e.target.value);
 
 savingsValue.textContent = ${savingsPercent}%;
 expensesSlider.value = 100 - savingsPercent;
 expensesValue.textContent = ${100 - savingsPercent}%;
 
 updateBudgetCalculation();
});

expensesSlider?.addEventListener('input', (e) => {
 const expensesPercent = parseInt(e.target.value);
 
 expensesValue.textContent = ${expensesPercent}%;
 savingsSlider.value = 100 - expensesPercent;
 savingsValue.textContent = ${100 - expensesPercent}%;
 
 updateBudgetCalculation();
});

// Calculate budget whenever input amount changes
budgetInput?.addEventListener('input', updateBudgetCalculation);

function updateBudgetCalculation() {
 const income = parseFloat(budgetInput.value);
 if (!income || isNaN(income)) {
     return;
 }
 
 const savingsPercent = parseInt(savingsSlider.value);
 const expensesPercent = parseInt(expensesSlider.value);
 
 const savingsAmount = income * (savingsPercent / 100);
 const expensesAmount = income * (expensesPercent / 100);
 
 showResult(`Monthly Budget:
            Savings: $${savingsAmount.toFixed(2)} (${savingsPercent}%)
            Expenses: $${expensesAmount.toFixed(2)} (${expensesPercent}%)`, 'success', 3);
}

// ==================== UTILITY FUNCTIONS ====================

// Function to show results underneath the calculators
function showResult(message, type, cardIndex) {
 let resultDisplay = document.querySelector(.form-card:nth-child(${cardIndex}) .result-display);
 
 // Create result display div if it doesn't exist
 if (!resultDisplay) {
     resultDisplay = document.createElement('div');
     resultDisplay.className = result-display ${type};
     document.querySelector(.form-card:nth-child(${cardIndex}) .form-content).appendChild(resultDisplay);
 }
 
 // Update content and styling
 resultDisplay.textContent = message;
 resultDisplay.className = result-display ${type};
 
 // Add animation
 resultDisplay.style.animation = 'fadeIn 0.5s';
}

// Format date to readable string
function formatDate(date) {
 const options = { year: 'numeric', month: 'long', day: 'numeric' };
 return date.toLocaleDateString(undefined, options);
}

// ==================== CHARTS FUNCTIONALITY ====================
// This section adds chart rendering to your page if needed

// Check if charts section exists in the DOM
const chartsSection = document.createElement('div');
chartsSection.className = 'charts-section';

// Add charts section after stats if it doesn't exist
if (!document.querySelector('.charts-section')) {
 const statsSection = document.querySelector('.stats');
 if (statsSection) {
     statsSection.after(chartsSection);
     
     // Create and append chart containers
     chartsSection.innerHTML = `
         <div class="chart-container">
             <h2>Expense Breakdown</h2>
             <canvas id="expenseChart" width="400" height="400"></canvas>
         </div>
         <div class="chart-grid">
             <div class="chart-item">
                 <h3>Savings Growth</h3>
                 <canvas id="savingsChart" width="400" height="200"></canvas>
             </div>
             <div class="chart-item">
                 <h3>Monthly Income</h3>
                 <canvas id="incomeChart" width="400" height="200"></canvas>
             </div>
         </div>
     `;
     
     // Load Chart.js from CDN if it's not already loaded
     if (typeof Chart === 'undefined') {
         const chartScript = document.createElement('script');
         chartScript.src = 'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js';
         chartScript.onload = initializeCharts;
         document.head.appendChild(chartScript);
     } else {
         initializeCharts();
     }
 }
}

// Initialize charts when Chart.js is loaded
function initializeCharts() {
 if (typeof Chart === 'undefined') return;
 
 // Sample data for demonstration - in a real app, this would come from your data source
 
 // Expense Breakdown Chart
 const expenseCtx = document.getElementById('expenseChart')?.getContext('2d');
 if (expenseCtx) {
     new Chart(expenseCtx, {
         type: 'doughnut',
         data: {
             labels: ['Housing', 'Food', 'Transportation', 'Entertainment', 'Utilities', 'Other'],
             datasets: [{
                 data: [35, 15, 12, 10, 18, 10],
                 backgroundColor: [
                     'rgba(0, 247, 255, 0.8)',
                     'rgba(65, 200, 255, 0.8)',
                     'rgba(105, 153, 255, 0.8)',
                     'rgba(145, 106, 255, 0.8)',
                     'rgba(185, 59, 255, 0.8)',
                     'rgba(225, 12, 255, 0.8)'
                 ],
                 borderColor: 'rgba(26, 35, 50, 0.1)',
                 borderWidth: 2
             }]
         },
         options: {
             responsive: true,
             plugins: {
                 legend: {
                     position: 'bottom',
                     labels: {
                         color: 'rgba(255, 255, 255, 0.7)'
                     }
                 }
             }
         }
     });
 }
 
 // Savings Growth Chart
 const savingsCtx = document.getElementById('savingsChart')?.getContext('2d');
 if (savingsCtx) {
     new Chart(savingsCtx, {
         type: 'line',
         data: {
             labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
             datasets: [{
                 label: 'Savings',
                 data: [500, 650, 800, 950, 1200, 1500],
                 borderColor: 'rgba(0, 247, 255, 0.8)',
                 backgroundColor: 'rgba(0, 247, 255, 0.2)',
                 tension: 0.4,
                 fill: true
             }]
         },
         options: {
             responsive: true,
             scales: {
                 y: {
                     beginAtZero: true,
                     grid: {
                         color: 'rgba(255, 255, 255, 0.1)'
                     },
                     ticks: {
                         color: 'rgba(255, 255, 255, 0.7)'
                     }
                 },
                 x: {
                     grid: {
                         color: 'rgba(255, 255, 255, 0.1)'
                     },
                     ticks: {
                         color: 'rgba(255, 255, 255, 0.7)'
                     }
                 }
             }
         }
     });
 }
 
 // Income Chart
 const incomeCtx = document.getElementById('incomeChart')?.getContext('2d');
 if (incomeCtx) {
     new Chart(incomeCtx, {
         type: 'bar',
         data: {
             labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
             datasets: [{
                 label: 'Income',
                 data: [3200, 3200, 3400, 3300, 3500, 4000],
                 backgroundColor: 'rgba(178, 75, 255, 0.8)'
             }]
         },
         options: {
             responsive: true,
             scales: {
                 y: {
                     beginAtZero: true,
                     grid: {
                         color: 'rgba(255, 255, 255, 0.1)'
                     },
                     ticks: {
                         color: 'rgba(255, 255, 255, 0.7)'
                     }
                 },
                 x: {
                     grid: {
                         color: 'rgba(255, 255, 255, 0.1)'
                     },
                     ticks: {
                         color: 'rgba(255, 255, 255, 0.7)'
                     }
                 }
             }
         }
     });
 }
}

// Add styles for the calculator results
const style = document.createElement('style');
style.textContent = `
 .result-display {
     margin-top: 15px;
     padding: 10px;
     border-radius: 8px;
     font-size: 0.9rem;
     transition: all 0.3s ease;
 }
 
 .result-display.success {
     background: rgba(0, 247, 255, 0.1);
     border-left: 3px solid #00f7ff;
     color: #ffffff;
 }
 
 .result-display.error {
     background: rgba(255, 88, 88, 0.1);
     border-left: 3px solid #ff5858;
     color: #ff5858;
 }
 
 @keyframes fadeIn {
     from { opacity: 0; transform: translateY(-10px); }
     to { opacity: 1; transform: translateY(0); }
 }
`;
document.head.appendChild(style);
});
