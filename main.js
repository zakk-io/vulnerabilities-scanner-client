let latestResult = null;

async function startScan() {
  const target = document.getElementById('targetInput').value;
  const output = document.getElementById('statusMessage');

  if (!target) {
    output.textContent = 'Please enter a target URL.';
    output.classList.remove('hidden');
    return;
  }

  try {
    output.textContent = 'Starting scan...';
    output.classList.remove('hidden');

    const scanResponse = await fetch('https://vulnerabilities-scanner-server.onrender.com/proxy/scans', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ target, type: 'passive', is_private: false })
    });

    const scanData = await scanResponse.json();
    const scanId = scanData.json_result.split('/').pop();

    const pollResult = async (id, interval = 3000, timeout = 300000) => {
      const startTime = Date.now();
      while (Date.now() - startTime < timeout) {
        const res = await fetch(`https://vulnerabilities-scanner-server.onrender.com/scans/${id}`);
        const data = await res.json();
        const progress = data.scan_info?.progress || 0;
        output.textContent = `Scan in progress... (${progress}%)`;
        if (data.scan_info?.status === 'finished') return data;
        await new Promise(r => setTimeout(r, interval));
      }
      throw new Error('Timeout waiting for scan');
    };

    const result = await pollResult(scanId);
    latestResult = result;
    output.textContent = 'Scan complete';

    document.querySelector(".scan-result-target").textContent = result.scan_info.target;
    document.querySelector(".scan-result-country").textContent = result.scan_info.user_country?.toUpperCase() || 'N/A';

    const screenshotDiv = document.querySelector(".screenshot-block");
    screenshotDiv.innerHTML = `<img src="${result.recon?.screenshot_url}" alt="Screenshot" class="w-full h-40 object-cover rounded">`;

    const techList = document.querySelector(".tech-list");
    techList.innerHTML = '';
    result.recon?.web_technologies?.forEach(t => {
      techList.innerHTML += `<li><span class="font-medium">${t.name}${t.version ? ' ' + t.version : ''}</span> - ${t.category}</li>`;
    });

    const vulnList = document.querySelector(".vuln-list");
    vulnList.innerHTML = '';
    result.vulnerabilities?.filter(v => v.category === 'web').forEach(v => {
      const icon = v.risk_level === 'low' ? 'text-blue-400' : v.risk_level === 'info' ? 'text-green-400' : 'text-red-400';
      vulnList.innerHTML += `<li class="flex items-start"><span class="${icon} mr-2">▪</span> ${v.title}</li>`;
    });

    const infraList = document.querySelector(".infra-list");
    infraList.innerHTML = '';
    result.vulnerabilities?.filter(v => v.category === 'network').forEach(v => {
      infraList.innerHTML += `<li class="flex items-start"><span class="text-blue-400 mr-2">▪</span> ${v.title}</li>`;
    });

    const portsList = document.querySelector(".ports-list");
    portsList.innerHTML = '';
    result.recon?.ports?.forEach(p => {
      portsList.innerHTML += `<li><span class="text-green-400 mr-2">●</span> ${p.port}/tcp - ${p.service} - ${p.product}</li>`;
    });

    await downloadPDF(result);

  } catch (err) {
    output.textContent = 'Scan failed: ' + err.message;
  }
}



async function handleDownload() {
  if (!latestResult || !latestResult.scan_info) {
    alert("⚠️ No scan results available yet. Please run a scan first.");
    return;
  }
  await downloadPDF(latestResult);
}



async function downloadPDF(result) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  let y = 10;

  doc.setFontSize(18);
  doc.text("Vulnissimo Detailed Scan Report", 14, y);
  y += 10;

  doc.setFontSize(12);
  doc.text(`Target URL: ${result.scan_info.target}`, 14, y); y += 8;
  doc.text(`Submitted From: ${result.scan_info.user_country?.toUpperCase() || 'N/A'}`, 14, y); y += 8;
  doc.text(`Scan Type: ${result.scan_info.type}`, 14, y); y += 8;
  doc.text(`Scan Mode: ${result.scan_info.scan_mode}`, 14, y); y += 8;
  doc.text(`Start Time: ${result.scan_info.start_time}`, 14, y); y += 8;
  doc.text(`End Time: ${result.scan_info.end_time}`, 14, y); y += 8;

  y += 4;
  doc.setFontSize(11);
  doc.text("Screenshot (URL):", 14, y); y += 6;
  if (result.recon?.screenshot_url) {
    doc.setTextColor(33, 150, 243);
    doc.textWithLink(result.recon.screenshot_url, 16, y, { url: result.recon.screenshot_url });
    doc.setTextColor(0, 0, 0);
    y += 6;
  } else {
    doc.text("Not available", 16, y); y += 6;
  }

  y += 4;
  doc.setFontSize(14);
  doc.text("Web Technologies", 14, y);
  y += 6;
  doc.setFontSize(10);
  if (result.recon?.web_technologies?.length) {
    result.recon.web_technologies.forEach(t => {
      doc.text(`• ${t.name}${t.version ? ' ' + t.version : ''} (${t.category})`, 16, y);
      y += 6;
    });
  } else {
    doc.text("No technologies identified.", 16, y); y += 6;
  }

  y += 4;
  doc.setFontSize(14);
  doc.text("Open Ports", 14, y);
  y += 6;
  doc.setFontSize(10);
  if (result.recon?.ports?.length) {
    result.recon.ports.forEach(p => {
      doc.text(`• ${p.port}/tcp - ${p.service} - ${p.product || 'N/A'}`, 16, y);
      y += 6;
    });
  } else {
    doc.text("No open ports detected.", 16, y); y += 6;
  }

  y += 4;
  doc.setFontSize(14);
  doc.text("Vulnerabilities", 14, y);
  y += 6;
  doc.setFontSize(10);
  if (result.vulnerabilities?.length) {
    result.vulnerabilities.forEach((v, i) => {
      doc.setFont(undefined, 'bold');
      doc.text(`${i + 1}. ${v.title}`, 16, y);
      y += 5;

      doc.setFont(undefined, 'normal');
      doc.text(`Risk Level: ${v.risk_level}`, 18, y); y += 5;
      doc.text(`Category: ${v.category}`, 18, y); y += 5;

      if (v.description) {
        const desc = doc.splitTextToSize(`Description: ${v.description}`, 180);
        doc.text(desc, 18, y);
        y += desc.length * 5;
      }

      if (v.recommendation) {
        const rec = doc.splitTextToSize(`Recommendation: ${v.recommendation}`, 180);
        doc.text(rec, 18, y);
        y += rec.length * 5;
      }

      if (v.evidence?.type === 'table') {
        doc.text("Evidence (table):", 18, y); y += 5;
        const headers = v.evidence.content.headers;
        const rows = v.evidence.content.rows;
        doc.setFont(undefined, 'bold');
        doc.text(headers.join(" | "), 20, y); y += 5;
        doc.setFont(undefined, 'normal');
        rows.forEach(r => {
          doc.text(r.join(" | "), 20, y);
          y += 5;
        });
      }

      y += 4;
      if (y > 270) { doc.addPage(); y = 10; }
    });
  } else {
    doc.text("No vulnerabilities detected.", 16, y); y += 6;
  }

  doc.save("Vulnissimo_Scan_Report.pdf");
}



// Register functions globally
window.startScan = startScan;
window.handleDownload = handleDownload;
window.latestResult = latestResult;
