import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout/Layout'
import Dashboard from './pages/Dashboard'
import LabsPage from './pages/LabsPage'
import LabDetail from './pages/LabDetail'
import DockerPage from './pages/DockerPage'
import CurriculumPage from './pages/CurriculumPage'
import ProgressPage from './pages/ProgressPage'

function App() {
  return (
    <BrowserRouter basename="/cyberlab">
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="labs" element={<LabsPage />} />
          <Route path="labs/:labId" element={<LabDetail />} />
          <Route path="docker" element={<DockerPage />} />
          <Route path="curriculum" element={<CurriculumPage />} />
          <Route path="progress" element={<ProgressPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
