// Run calculations on page load
document.addEventListener('DOMContentLoaded', function () {
    calculateEMI();
    calculateInvestment();
});

// EMI Calculator
function calculateEMI() {
    const loanAmount = parseFloat(document.getElementById('loanAmount').value);
    const interestRate = parseFloat(document.getElementById('interestRate').value) / 100 / 12;
    const loanTerm = parseFloat(document.getElementById('loanTerm').value) * 12;

    if (!loanAmount || !interestRate || !loanTerm) {
        showResult('emiResult', 'Please fill all fields');
        return;
    }

    const emi = (loanAmount * interestRate * Math.pow(1 + interestRate, loanTerm)) /
        (Math.pow(1 + interestRate, loanTerm) - 1);
    const totalPayment = emi * loanTerm;
    const totalInterest = totalPayment - loanAmount;

    showResult('emiResult', `
        EMI: ₹${emi.toFixed(2)}<br>
        Total Interest: ₹${totalInterest.toFixed(2)}<br>
        Total Payment: ₹${totalPayment.toFixed(2)}
    `);

    // Update chart
    updateEMIChart(loanAmount, totalInterest);
}

// Investment Calculator
function calculateInvestment() {
    const principal = parseFloat(document.getElementById('principalAmount').value);
    const rate = parseFloat(document.getElementById('returnRate').value) / 100;
    const time = parseFloat(document.getElementById('timePeriod').value);

    if (!principal || !rate || !time) {
        showResult('investmentResult', 'Please fill all fields');
        return;
    }

    const amount = principal * Math.pow(1 + rate, time);
    const interest = amount - principal;

    showResult('investmentResult', `
        Final Amount: ₹${amount.toFixed(2)}<br>
        Total Returns: ₹${interest.toFixed(2)}
    `);

    // Update chart
    updateInvestmentChart(principal, rate, time);
}

// Show result with animation
function showResult(elementId, message) {
    const element = document.getElementById(elementId);
    element.innerHTML = message;
    element.classList.add('show');
    element.style.animation = 'fadeIn 0.5s ease-in-out';
}

// Update EMI Chart
function updateEMIChart(principal, interest) {
    const data = [
        { label: 'Principal', value: principal, color: '#00f7ff' },
        { label: 'Interest', value: interest, color: '#b24bff' }
    ];

    // Clear previous chart
    document.getElementById('emiChart').innerHTML = '';

    const width = document.getElementById('emiChart').clientWidth;
    const height = document.getElementById('emiChart').clientHeight;
    const radius = Math.min(width, height) / 2 * 0.8;

    const svg = d3.select('#emiChart')
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .append('g')
        .attr('transform', `translate(${width / 2}, ${height / 2})`);

    const arc = d3.arc()
        .innerRadius(radius * 0.6)
        .outerRadius(radius);

    const pie = d3.pie()
        .value(d => d.value)
        .sort(null);

    // Add donut chart segments
    svg.selectAll('path')
        .data(pie(data))
        .enter()
        .append('path')
        .attr('d', arc)
        .attr('fill', d => d.data.color)
        .attr('stroke', '#0c121f')
        .attr('stroke-width', 2);

    // Add center text
    svg.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', '0.35em')
        .style('font-size', '14px')
        .style('fill', '#ffffff')
        .text(`₹${(principal + interest).toLocaleString()}`);

    // Add legend
    svg.selectAll('dots')
        .data(data)
        .enter()
        .append('circle')
        .attr('cx', -radius + 10)
        .attr('cy', (d, i) => -radius + 20 + i * 20)
        .attr('r', 5)
        .style('fill', d => d.color);

    svg.selectAll('labels')
        .data(data)
        .enter()
        .append('text')
        .attr('x', -radius + 20)
        .attr('y', (d, i) => -radius + 20 + i * 20)
        .attr('dy', '0.35em')
        .style('fill', '#ffffff')
        .style('font-size', '10px')
        .text(d => `${d.label}: ₹${d.value.toLocaleString()}`);
}

// Update Investment Chart
function updateInvestmentChart(principal, rate, years) {
    // Clear previous chart
    document.getElementById('investmentChart').innerHTML = '';

    const width = document.getElementById('investmentChart').clientWidth;
    const height = document.getElementById('investmentChart').clientHeight;
    const margin = { top: 10, right: 30, bottom: 30, left: 50 };
    const chartWidth = width - margin.left - margin.right;
    const chartHeight = height - margin.top - margin.bottom;

    // Generate yearly data
    const data = [];
    for (let i = 0; i <= years; i++) {
        const amount = principal * Math.pow(1 + rate, i);
        data.push({
            year: i,
            amount: amount
        });
    }

    const svg = d3.select('#investmentChart')
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .append('g')
        .attr('transform', `translate(${margin.left}, ${margin.top})`);

    // X axis
    const x = d3.scaleLinear()
        .domain([0, years])
        .range([0, chartWidth]);

    svg.append('g')
        .attr('transform', `translate(0, ${chartHeight})`)
        .call(d3.axisBottom(x).ticks(5))
        .selectAll('text')
        .style('fill', '#ffffff');

    // Y axis
    const maxAmount = data[data.length - 1].amount;
    const y = d3.scaleLinear()
        .domain([0, maxAmount * 1.1])
        .range([chartHeight, 0]);

    svg.append('g')
        .call(d3.axisLeft(y).ticks(5).tickFormat(d => `${(d / 1000).toFixed(0)}k`))
        .selectAll('text')
        .style('fill', '#ffffff');

    // Add gradient area
    svg.append('path')
        .datum(data)
        .attr('fill', '#4ecca3')
        .attr('fill-opacity', 0.3)
        .attr('stroke', 'none')
        .attr('d', d3.area()
            .x(d => x(d.year))
            .y0(chartHeight)
            .y1(d => y(d.amount))
        );

    // Add line
    svg.append('path')
        .datum(data)
        .attr('fill', 'none')
        .attr('stroke', '#4ecca3')
        .attr('stroke-width', 2)
        .attr('d', d3.line()
            .x(d => x(d.year))
            .y(d => y(d.amount))
            .curve(d3.curveMonotoneX)
        );

    // Add dots for each year
    svg.selectAll('circle')
        .data(data)
        .enter()
        .append('circle')
        .attr('cx', d => x(d.year))
        .attr('cy', d => y(d.amount))
        .attr('r', 3)
        .attr('fill', '#4ecca3');
}
