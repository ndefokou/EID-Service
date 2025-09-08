import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { EidFlowProvider } from './contexts/EidFlowContext';

import Header from './components/common/Header/Header';
import Footer from './components/common/Footer/Footer';
import Home from './pages/Home/Home';
import Dashboard from './pages/Dashboard/Dashboard';
import EidCallback from './pages/EidCallback/EidCallback';
import NotFound from './pages/NotFound/NotFound';

import './assets/styles/main.scss';

function App() {
  return (
    <Router>
      <EidFlowProvider>
        <Header />
        <main className="app-main">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/eid-callback" element={<EidCallback />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </main>
        <Footer />
      </EidFlowProvider>
    </Router>
  );
}

export default App;