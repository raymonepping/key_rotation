import React, { Component } from 'react';

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('ErrorBoundary caught:', error, errorInfo);
    this.setState({ errorInfo });
  }

  render() {
    if (!this.state.hasError) return this.props.children;

    return (
      <div style={{
        minHeight: '100vh',
        background: 'var(--vr-ground)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '32px',
        fontFamily: 'var(--font-sans)',
      }}>
        <div className="panel" style={{ maxWidth: 560, width: '100%' }}>
          <span className="pill denied" style={{ marginBottom: 12, display: 'inline-block' }}>
            Runtime error
          </span>
          <h2 style={{ color: 'var(--vr-denied)', marginTop: 0 }}>Something went wrong</h2>
          <p>An unexpected error occurred. Check the browser console for details.</p>
          {this.state.error && (
            <div className="output-well denied" style={{ marginTop: 12 }}>
              {this.state.error.toString()}
            </div>
          )}
          {this.state.errorInfo && (
            <details style={{ marginTop: 12 }}>
              <summary className="meta" style={{ cursor: 'pointer' }}>Component stack</summary>
              <div className="output-well" style={{ marginTop: 8, whiteSpace: 'pre-wrap' }}>
                {this.state.errorInfo.componentStack}
              </div>
            </details>
          )}
        </div>
      </div>
    );
  }
}
