window.onload = () => {
    document.getElementById('login-btn').addEventListener('click', () => {
        const username = document.getElementById('username').value
        const password = document.getElementById('password').value
        
        if (!username || !password) {
            return
        }

        axios.post('/api/login', {
            username, password
        })
        .then(res => {
            if (res.data.success) window.location.pathname = '/'
            else alert(res.data.reason)
        })
    })
}