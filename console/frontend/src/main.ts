import { createApp } from 'vue'
import App from './App.vue'
import './styles.css'
import { startPolling } from './api'

createApp(App).mount('#app')
startPolling()
