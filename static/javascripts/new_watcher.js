function onTargetEnvSelectChange() {
  const target = document.getElementById('target-env').value
  let serverPort = ''
  switch (target) {
    case 'node':
    serverPort = '3000'
    break
    case 'flask':
    serverPort = '5000'
    break
  }

  document.getElementById('server-port').value = serverPort
  if (!document.getElementById('server-port-form-group').classList.contains('is-filled')) document.getElementById('server-port-form-group').classList.add('is-filled')
}

function showError() {
  const errDiv = document.getElementById('error-row')
  errDiv.classList.toggle('show-error')
  setTimeout(() => errDiv.classList.toggle('show-error'), 1000)
}

window.onload = () => {
  document.getElementById('deploy-server-btn').addEventListener('click', () => {
    const url = document.getElementById('repo-url').value
    const serverName = document.getElementById('server-name').value
    const platform = document.getElementById('target-env').value
    const envVars = document.getElementById('env').value
    const errSpan = document.querySelector('div#error-row span')
    if (!url || !serverName || !platform) {
      errSpan.textContent = 'Fill all required text fields.'
      showError()
      return
    }

    axios.post('/api/watches', {
      name: serverName,
      repopath: url,
      target: platform,
      environment: envVars
    })
    .then((res) => {
      if (res.data.success) {
        window.location.pathname = '/watches/' + res.data.data
      } else {
        alert(res.data.reason)
      }
    })
  })
}