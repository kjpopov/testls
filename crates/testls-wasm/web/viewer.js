const input = document.querySelector('#capture');
const report = document.querySelector('#report');
let worker;

input.addEventListener('change', () => {
  worker?.terminate();
  const file = input.files[0];
  if (!file) {
    report.textContent = '';
    return;
  }
  report.textContent = 'Reading capture…';
  const current = new Worker(new URL('./worker.js', import.meta.url), {type: 'module'});
  worker = current;
  const finish = text => {
    if (worker === current) report.textContent = text;
    current.terminate();
  };
  current.onmessage = event => finish(event.data);
  current.onerror = () => finish('Could not start the capture reader.');
  current.postMessage(file);
});
