window.onload = () => {
    if (document.getElementById('refresh-btn')) {
        document.getElementById('refresh-btn').addEventListener('click', () => {
            const sp = window.location.pathname.split('/')
            axios.post(`/api/watches/${sp[sp.length - 1]}/update`)
            .then(res => {
                if (res.data.success) {
                    window.location.reload()
                } else {
                    alert(res.data.reason)
                }
            })
        })    
    }
    document.getElementById('remove-deploy-btn').addEventListener('click', () => {
        const really = confirm('Deployment will be DELETED! Continue?')
        if (!really) return
        const sp = window.location.pathname.split('/')
        axios.delete(`/api/watches/${sp[sp.length - 1]}`)
        .then(res => {
            if (res.data.success) {
                window.location.pathname = '/watches'
            } else {
                alert(res.data.reason)
            }
        })
    })
}