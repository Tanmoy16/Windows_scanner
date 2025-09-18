function showPage(pageId) {
  document.querySelectorAll('.page').forEach(page => {
    page.classList.remove('active');
  });
  document.getElementById(pageId).classList.add('active');
}

function startScan() {
  let progress = 0;
  const progressBar = document.getElementById("progress");
  const progressText = document.getElementById("progress-text");

  const interval = setInterval(() => {
    if (progress >= 100) {
      clearInterval(interval);
      progressText.textContent = "Scan Completed!";
    } else {
      progress += 10;
      progressBar.style.width = progress + "%";
      progressText.textContent = progress + "%";
    }
  }, 500);
}
