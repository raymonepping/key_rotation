import React, { useState } from 'react';
import Shell from './components/Shell.jsx';
import SecretStatusPanel from './components/SecretStatusPanel.jsx';
import TransitDemoPanel from './components/TransitDemoPanel.jsx';
import ApiKeyPanel from './components/ApiKeyPanel.jsx';
import RotationLogPanel from './components/RotationLogPanel.jsx';

export default function App() {
  const [view, setView] = useState('status');

  return (
    <Shell view={view} onView={setView}>
      {view === 'status'  && <SecretStatusPanel />}
      {view === 'transit' && <TransitDemoPanel />}
      {view === 'apikey'  && <ApiKeyPanel />}
      {view === 'log'     && <RotationLogPanel />}
    </Shell>
  );
}
