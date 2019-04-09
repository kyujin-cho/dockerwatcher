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
      const archive = document.getElementById('archive').files
      const serverName = document.getElementById('server-name').value
      const platform = document.getElementById('target-env').value
      const envVars = document.getElementById('env').value
      const errSpan = document.querySelector('div#error-row span')
      if (!serverName || !platform || !archive || !archive[0]) {
        errSpan.textContent = 'Fill all required form fields.'
        showError()
        return
      }
      if (serverName.substring(0, 1).toLowerCase() != serverName.substring(0, 1) || !isNaN(parseInt(serverName.substring(0, 1)))) {
        errSpan.textContent = 'Server name must start with lowercase alphabet'
        showError()
        return
      }
      const data = new FormData()
      data.append('name', serverName)
      data.append('target', platform)
      data.append('environment', envVars)
      data.append('deployType', 'archive')
      data.append('archive', archive[0])
      axios.post('/api/watches', data)
      .then((res) => {
        if (res.data.success) {
          window.location.pathname = '/watches/' + res.data.data
        } else {
          alert(res.data.reason)
        }
      })
      .catch((err) => {
        alert(err)
      })
    })
  }