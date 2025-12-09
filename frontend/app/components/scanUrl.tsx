'use client'
import React, { useState } from 'react';
import { Search, Shield, AlertTriangle, CheckCircle, XCircle, Loader } from 'lucide-react';
import axios from 'axios';

interface UrlData {
  link: string;
}

interface ScanResult {
  status: 'safe' | 'suspicious' | 'dangerous';
  message: string;
  details?: string[];
}

const Scanurl = () => {
  const [urlData, setUrlData] = useState<UrlData>({ link: '' });
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string>('');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newLink: string = e.target.value;
    setUrlData({ link: newLink });
    setError('');
  };

  const validateUrl = (url: string): boolean => {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  };

  const handleScan = async () => {
    if (!urlData.link.trim()) {
      setError('Please enter a URL to scan');
      return;
    }

    if (!validateUrl(urlData.link)) {
      setError('Please enter a valid URL (e.g., https://example.com)');
      return;
    }

    setIsScanning(true);
    setError('');
    setScanResult(null);

    try {
      const response = await axios.post('http://localhost:8000/api/scan', {
        link: urlData.link
      });

      // Map API response to ScanResult interface
      const result: ScanResult = {
        status: response.data.status,
        message: response.data.message || getDefaultMessage(response.data.status),
        details: response.data.details || []
      };

      setScanResult(result);
    } catch (err) {
      setError('Failed to scan URL. Please try again later.');
      console.error('Scan error:', err);
    } finally {
      setIsScanning(false);
    }
  };

  const getDefaultMessage = (status: string): string => {
    switch (status) {
      case 'safe':
        return 'This URL appears to be safe';
      case 'suspicious':
        return 'This URL shows suspicious characteristics';
      case 'dangerous':
        return 'Warning: This URL is potentially dangerous';
      default:
        return 'Scan completed';
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      handleScan();
    }
  };

  const getResultIcon = () => {
    if (!scanResult) return null;
    
    switch (scanResult.status) {
      case 'safe':
        return <CheckCircle className="h-16 w-16 text-green-500" />;
      case 'suspicious':
        return <AlertTriangle className="h-16 w-16 text-yellow-500" />;
      case 'dangerous':
        return <XCircle className="h-16 w-16 text-red-500" />;
      default:
        return null;
    }
  };

  const getResultColor = () => {
    if (!scanResult) return '';
    
    switch (scanResult.status) {
      case 'safe':
        return 'bg-green-50 border-green-200';
      case 'suspicious':
        return 'bg-yellow-50 border-yellow-200';
      case 'dangerous':
        return 'bg-red-50 border-red-200';
      default:
        return '';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-12 px-4">
      <div className="max-w-4xl mx-auto">
        {/* Header Section */}
        <div className="text-center mb-12">
          <div className="flex justify-center mb-4">
            <Shield className="h-16 w-16 text-blue-600" />
          </div>
          <h1 className="text-4xl font-bold text-gray-800 mb-3">
            Phishing URL Scanner
          </h1>
          <p className="text-gray-600 text-lg">
            Enter a URL below to check if it&apos;s safe or potentially dangerous
          </p>
        </div>

        {/* Scan Input Card */}
        <div className="bg-white rounded-xl shadow-lg p-8 mb-8">
          <div className="space-y-4">
            <label htmlFor="url" className="block text-sm font-semibold text-gray-700 mb-2">
              Website URL
            </label>
            
            <div className="flex flex-col sm:flex-row gap-3">
              <input 
                type="text" 
                name="url" 
                id="url"
                placeholder="https://example.com" 
                value={urlData.link} 
                onChange={handleChange}
                onKeyPress={handleKeyPress}
                className="flex-1 px-4 py-3 border-2 border-gray-300 rounded-lg focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition duration-200"
              />
              
              <button
                onClick={handleScan}
                disabled={isScanning}
                className="px-8 py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-4 focus:ring-blue-300 disabled:bg-gray-400 disabled:cursor-not-allowed transition duration-200 flex items-center justify-center gap-2"
              >
                {isScanning ? (
                  <>
                    <Loader className="h-5 w-5 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Search className="h-5 w-5" />
                    Scan URL
                  </>
                )}
              </button>
            </div>

            {error && (
              <div className="flex items-center gap-2 text-red-600 bg-red-50 p-3 rounded-lg">
                <AlertTriangle className="h-5 w-5" />
                <span>{error}</span>
              </div>
            )}
          </div>
        </div>

        {/* Scanning Animation */}
        {isScanning && (
          <div className="bg-white rounded-xl shadow-lg p-8 text-center">
            <Loader className="h-12 w-12 text-blue-600 animate-spin mx-auto mb-4" />
            <p className="text-gray-600 text-lg">Analyzing URL security...</p>
          </div>
        )}

        {/* Results Section */}
        {scanResult && !isScanning && (
          <div className={`rounded-xl shadow-lg p-8 border-2 ${getResultColor()}`}>
            <div className="text-center mb-6">
              <div className="flex justify-center mb-4">
                {getResultIcon()}
              </div>
              <h2 className="text-2xl font-bold text-gray-800 mb-2">
                {scanResult.message}
              </h2>
            </div>

            {scanResult.details && scanResult.details.length > 0 && (
              <div className="mt-6">
                <h3 className="text-lg font-semibold text-gray-700 mb-3">
                  Scan Details:
                </h3>
                <ul className="space-y-2">
                  {scanResult.details.map((detail, index) => (
                    <li key={index} className="flex items-start gap-2">
                      <CheckCircle className="h-5 w-5 text-green-500 mt-0.5 flex-shrink-0" />
                      <span className="text-gray-700">{detail}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="mt-6 pt-6 border-t border-gray-200">
              <button
                onClick={() => {
                  setUrlData({ link: '' });
                  setScanResult(null);
                }}
                className="w-full px-6 py-3 bg-gray-200 text-gray-700 font-semibold rounded-lg hover:bg-gray-300 transition duration-200"
              >
                Scan Another URL
              </button>
            </div>
          </div>
        )}

        {/* Info Section */}
        <div className="mt-12 bg-white rounded-xl shadow-lg p-8">
          <h3 className="text-xl font-bold text-gray-800 mb-4">
            How it works
          </h3>
          <div className="grid md:grid-cols-3 gap-6">
            <div className="text-center">
              <div className="bg-blue-100 rounded-full w-12 h-12 flex items-center justify-center mx-auto mb-3">
                <span className="text-blue-600 font-bold">1</span>
              </div>
              <h4 className="font-semibold text-gray-800 mb-2">Enter URL</h4>
              <p className="text-gray-600 text-sm">Paste the suspicious website link</p>
            </div>
            <div className="text-center">
              <div className="bg-blue-100 rounded-full w-12 h-12 flex items-center justify-center mx-auto mb-3">
                <span className="text-blue-600 font-bold">2</span>
              </div>
              <h4 className="font-semibold text-gray-800 mb-2">Analyze</h4>
              <p className="text-gray-600 text-sm">Our system checks for threats</p>
            </div>
            <div className="text-center">
              <div className="bg-blue-100 rounded-full w-12 h-12 flex items-center justify-center mx-auto mb-3">
                <span className="text-blue-600 font-bold">3</span>
              </div>
              <h4 className="font-semibold text-gray-800 mb-2">Get Results</h4>
              <p className="text-gray-600 text-sm">Receive detailed safety report</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Scanurl;