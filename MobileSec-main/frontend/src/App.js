import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/layout/Layout';
import Dashboard from './pages/Dashboard';
import Upload from './pages/Upload';
import Scans from './pages/Scans';
import ScanDetail from './pages/ScanDetail';
import FixSuggestions from './pages/FixSuggestions';
import ReportsList from './pages/ReportsList';
// ...
import Settings from './pages/Settings';
import { SettingsProvider } from './context/SettingsContext';

// Simple fallback for 404
const NotFound = () => (
  <div className="text-center p-10">
    <h2 className="text-3xl font-bold text-slate-300">404 - Page Not Found</h2>
    <p className="text-slate-500 mt-2">The page you are looking for does not exist.</p>
  </div>
);


function App() {
  return (
    <SettingsProvider>
      <Router>
        <Layout>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/upload" element={<Upload />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
            <Route path="/scans/:scanId/suggestions" element={<FixSuggestions />} />
            <Route path="/reports" element={<ReportsList />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Layout>
      </Router>
    </SettingsProvider>
  );
}

export default App;
